package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/packethost/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tinkerbell/tink/client/listener"
	"github.com/tinkerbell/tink/db"
	rpcServer "github.com/tinkerbell/tink/grpc-server"
	httpServer "github.com/tinkerbell/tink/http-server"
)

var (
	// version is set at build time.
	version = "devel"

	rootCmd = &cobra.Command{
		Use:     "tink-server",
		Short:   "Tinkerbell provisioning and workflow engine",
		Long:    "Tinkerbell provisioning and workflow engine",
		Version: version,
		Run: func(cmd *cobra.Command, args []string) {
			log, err := log.Init("github.com/tinkerbell/tink")
			if err != nil {
				panic(err)
			}

			defer log.Close()
			log.Info("starting version " + version)

			ctx, closer := context.WithCancel(context.Background())
			errCh := make(chan error, 2)

			facility, err := cmd.PersistentFlags().GetString("facility")
			if err != nil {
				log.Fatal(err)
			}
			if facility == "" {
				facility = os.Getenv("FACILITY")
			}

			log = log.With("facility", facility)

			// TODO(gianarb): I moved this up because we need to be sure that both
			// connection, the one used for the resources and the one used for
			// listening to events and notification are coming in the same way.
			// BUT we should be using the right flags
			connInfo := fmt.Sprintf("dbname=%s user=%s password=%s sslmode=%s",
				os.Getenv("PGDATABASE"),
				os.Getenv("PGUSER"),
				os.Getenv("PGPASSWORD"),
				os.Getenv("PGSSLMODE"),
			)

			dbCon, err := sql.Open("postgres", connInfo)
			if err != nil {
				log.Fatal(err)
			}

			tinkDB := db.Connect(dbCon, log)

			_, onlyMigration := os.LookupEnv("ONLY_MIGRATION")
			if onlyMigration {
				log.Info("Applying migrations. This process will end when migrations will take place.")
				numAppliedMigrations, err := tinkDB.Migrate()
				if err != nil {
					log.Fatal(err)
				}
				log.With("num_applied_migrations", numAppliedMigrations).Info("Migrations applied successfully")
				os.Exit(0)
			}

			err = listener.Init(connInfo)
			if err != nil {
				log.Fatal(err)
				panic(err)
			}

			go tinkDB.PurgeEvents(errCh)

			numAvailableMigrations, err := tinkDB.CheckRequiredMigrations()
			if err != nil {
				log.Fatal(err)
			}
			if numAvailableMigrations != 0 {
				log.Info("Your database schema is not up to date. Please apply migrations running tink-server with env var ONLY_MIGRATION set.")
			}

			tlsCert, certPEM, modT, err := getCerts(cmd.PersistentFlags())
			if err != nil {
				log.Fatal(err)
			}

			rpcServer.SetupGRPC(ctx, log, facility, tinkDB, certPEM, tlsCert, modT, errCh)
			httpServer.SetupHTTP(ctx, log, certPEM, modT, errCh)

			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

			select {
			case err = <-errCh:
				log.Fatal(err)
			case sig := <-sigs:
				log.With("signal", sig.String()).Info("signal received, stopping servers")
			}
			closer()

			// wait for grpc server to shutdown
			err = <-errCh
			if err != nil {
				log.Fatal(err)
			}
			err = <-errCh
			if err != nil {
				log.Fatal(err)
			}
		},
	}
)

func main() {
	rootCmd.PersistentFlags().String("ca-cert", "", "File containing the ca certificate")
	rootCmd.PersistentFlags().String("tls-cert", "bundle.pem", "File containing the tls certificate")
	rootCmd.PersistentFlags().String("tls-key", "server-key.pem", "File containing the tls private key")
	rootCmd.PersistentFlags().String("facility", "", "Facility")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getCerts(flagSet *pflag.FlagSet) (tls.Certificate, []byte, time.Time, error) {
	var (
		modT         time.Time
		caCertBytes  []byte
		tlsCertBytes []byte
		tlsKeyBytes  []byte
	)

	caPath, err := flagSet.GetString("ca-cert")
	if err != nil {
		return tls.Certificate{}, tlsCertBytes, modT, err
	}

	if caPath != "" {
		ca, modified, err := readFromFile(caPath)
		if err != nil {
			return tls.Certificate{}, tlsCertBytes, modT, fmt.Errorf("failed to read ca cert: %w", err)
		}

		if modified.After(modT) {
			modT = modified
		}

		caCertBytes = ca
	}

	certPath, err := flagSet.GetString("tls-cert")
	if err != nil {
		return tls.Certificate{}, tlsCertBytes, modT, err
	}

	if certPath != "" {
		cert, modified, err := readFromFile(certPath)
		if err != nil {
			return tls.Certificate{}, tlsCertBytes, modT, fmt.Errorf("failed to read tls cert: %w", err)
		}

		if modified.After(modT) {
			modT = modified
		}

		tlsCertBytes = cert
	}

	keyPath, err := flagSet.GetString("tls-key")
	if err != nil {
		return tls.Certificate{}, tlsCertBytes, modT, err
	}

	if keyPath != "" {
		key, modified, err := readFromFile(keyPath)
		if err != nil {
			return tls.Certificate{}, tlsCertBytes, modT, fmt.Errorf("failed to read tls key: %w", err)
		}

		if modified.After(modT) {
			modT = modified
		}

		tlsKeyBytes = key
	}

	// Fail if we haven't read in a tls certificate
	if len(tlsCertBytes) == 0 {
		return tls.Certificate{}, tlsCertBytes, modT, fmt.Errorf("--tls-cert is required")
	}

	// Fail if we haven't read in a tls key
	if len(tlsKeyBytes) == 0 {
		return tls.Certificate{}, tlsCertBytes, modT, fmt.Errorf("--tls-key is required")
	}

	// If we read in a separate ca certificate, concatenate it with the tls cert
	if len(caCertBytes) > 0 {
		tlsCertBytes = append(tlsCertBytes, caCertBytes...)
	}

	cert, err := tls.X509KeyPair(tlsCertBytes, tlsKeyBytes)
	if err != nil {
		return cert, tlsCertBytes, modT, fmt.Errorf("failed to ingest TLS files: %w", err)
	}

	return cert, tlsCertBytes, modT, nil
}

func readFromFile(filePath string) ([]byte, time.Time, error) {
	var modified time.Time

	f, err := os.Open(filePath)
	if err != nil {
		return nil, modified, err
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, modified, err
	}

	modified = stat.ModTime()

	contents, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, modified, err
	}

	return contents, modified, nil
}

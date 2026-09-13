import Config

# Log to stderr so the CLI's stdout stays machine-readable (e.g. with --json).
config :logger, :console,
  device: :standard_error,
  format: "$time $metadata[$level] $message\n"

config :logger, level: :info

# Import environment specific config
import_config "#{config_env()}.exs"

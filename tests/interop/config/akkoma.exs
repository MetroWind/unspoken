import Config

config :pleroma, Pleroma.Web.Endpoint,
  url: [host: "akkoma.test", scheme: "http", port: 4000],
  http: [ip: {0, 0, 0, 0}, port: 4000],
  secret_key_base:
    "interop-secret-key-base-00000000000000000000000000000000000000000000"

config :pleroma, :instance,
  name: "Akkoma Interop",
  email: "interop@akkoma.test",
  notify_email: "interop@akkoma.test",
  limit: 5_000,
  registrations_open: true,
  federating: true

config :pleroma, :database, rum_enabled: false

config :pleroma, Pleroma.Repo,
  adapter: Ecto.Adapters.Postgres,
  username: "akkoma",
  password: "akkoma",
  database: "akkoma",
  hostname: "postgres",
  pool_size: 10

config :pleroma, configurable_from_database: false

config :pleroma, :media_proxy, enabled: false

config :pleroma, Pleroma.Upload,
  base_url: "http://akkoma.test:4000/media/"

config :pleroma, Pleroma.Captcha, enabled: false

config :pleroma, :activitypub, sign_object_fetches: true

config :web_push_encryption, :vapid_details,
  subject: "mailto:interop@akkoma.test",
  public_key:
    "BAwwj2dNtPYSWmw7AAI8K8c2tUM0ZL6qmQ6v2lYxfO5yNt0yDzAhss6" <>
    "LpARs3yH0pMknUjagQyMXuRC5RxTZd2Q",
  private_key: "FHOK41t3P1pYcwr66AzDng2uDlKp7bbLEbXalH4hRyM"

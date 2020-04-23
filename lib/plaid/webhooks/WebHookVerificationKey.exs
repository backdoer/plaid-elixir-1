defmodule Plaid.Webhooks.WebHookVerificationKey do
  @moduledoc """
  """
  defmodule VerificationKey do
    @type t :: %__MODULE__{
            alg: String.t(),
            ecreate_at: String.t(),
            crv: String.t(),
            expired_at: String.t(),
            kid: String.t(),
            kty: String.t(),
            use: String.t(),
            x: String.t(),
            y: String.t()
          }

    @derive Jason.Encoder
    defstruct [
      :alg,
      :ecreate_at,
      :crv,
      :expired_at,
      :kid,
      :kty,
      :use,
      :x,
      :y
    ]
  end

  @type t :: %__MODULE__{
          key: VerificationKey.t(),
          request_id: String.t()
        }

  @derive Jason.Encoder
  defstruct [
    :key,
    :request_id
  ]
end

defmodule Plaid.Webhook do
  @moduledoc """
  Creates a plaid Event from webhook's payload if signature is valid.
  """

  import Plaid, only: [make_request_with_cred: 4, validate_cred: 1]

  alias Plaid.Utils

  @endpoint :webhook_verification_key

  @type params :: %{required(atom) => String.t()}
  @type config :: %{required(atom) => String.t()}

  defmodule AuthWebHook do
    @moduledoc """
    """
    @type t :: %__MODULE__{
            webhook_type: String.t(),
            webhook_code: String.t(),
            item_id: String.t(),
            account_id: String.t(),
            error: Plaid.Error.t()
          }

    @derive Jason.Encoder
    defstruct [
      :webhook_type,
      :webhook_code,
      :item_id,
      :account_id,
      :error
    ]
  end

  defmodule WebHookVerificationKey do
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

  @doc """
  Constructs an plaid event after validating the jwt_string.

  Parameters
  ```
  %{
    body: "payload_received_from_webhook",
    client_id: "client_identifier",
    jwt_string: "plaid_verification_header",
    secret: "plaid_env_secret"

  ```
  """
  @spec construct_webhook_event(params, config | nil) ::
          {:ok, map()} | {:error, any}
        when params: %{
               :body => String.t(),
               :client_id => String.t(),
               :jwt_string => String.t(),
               :secret => String.t()
             }
  def construct_webhook_event(params, config \\ %{}) do
    with {:ok, %{"alg" => "ES256", "kid" => kid}} <- Joken.peek_header(params.jwt_string),
         response =
           retreive_public_key(
             %{client_id: params.client_id, secret: params.secret, key_id: kid},
             config
           ) do
      {:ok, response}
    else
      error ->
        error
    end
  end

  @spec retreive_public_key(map(), config | nil) :: {:ok, map} | {:error, Plaid.Error.t()}
  defp retreive_public_key(params, config) do
    config = validate_cred(config)
    endpoint = "#{@endpoint}/get"

    make_request_with_cred(:post, endpoint, config, params)
    |> Utils.handle_resp(@endpoint)
    |> IO.inspect()
  end
end

defmodule Plaid.Webhook do
  @moduledoc """
  Creates a Plaid Event from webhook's payload if signature is valid.

  Verification flow following docs::: plaid.com/docs/#webhook-verification
  """

  import Plaid, only: [make_request_with_cred: 4, validate_cred: 1]

  alias Plaid.Utils

  @endpoint :webhook_verification_key

  @type params :: %{required(atom) => String.t()}
  @type config :: %{required(atom) => String.t()}

  defmodule WebHookVerificationKey do
    @type t :: %__MODULE__{
            key: map,
            request_id: String.t()
          }

    @derive Jason.Encoder
    defstruct [
      :key,
      :request_id
    ]
  end

  defmodule Event do
    @type t :: %__MODULE__{
            type: String.t(),
            data: map
          }

    @derive Jason.Encoder
    defstruct [
      :type,
      :data
    ]
  end

  @doc """
  Constructs an plaid event after validating the jwt_string

  Parameters
  ```
  %{
    body: "payload_received_from_webhook",
    client_id: "client_identifier",
    jwt_string: "plaid_verification_header",
    secret: "plaid_env_secret"
  }
  ```
  """
  @spec construct_event(params, config | nil) ::
          {:ok, map()} | {:error, any}
        when params: %{
               :body => String.t(),
               :client_id => String.t(),
               :jwt_string => String.t(),
               :secret => String.t()
             }
  def construct_event(params, config \\ %{}) do
    with {:ok, %{"alg" => "ES256", "kid" => kid}} <- Joken.peek_header(params.jwt_string),
         {:ok, %Plaid.Webhook.WebHookVerificationKey{} = wvk} <-
           retreive_public_key(
             %{client_id: params.client_id, secret: params.secret, key_id: kid},
             config
           ),
         {:ok,
          %{
            "iat" => iat,
            "request_body_sha256" => body_sha256
          }} <- validate_the_signature(params.jwt_string, wvk),
         true <- less_than_five_minutes_ago(iat),
         true <- bodies_match(params.body, body_sha256) do
      create_event(params.body)
    else
      {:ok, %{"alg" => _alg}} ->
        {:error, :unauthorized, reason: "incorrect alg"}

      {:erro, %Plaid.Error{}} ->
        {:error, :unauthorized, reason: "invalid plaid credentials"}

      false ->
        {:error, :unauthorized, reason: "received too late"}

      _error ->
        {:error, :unauthorized}
    end
  end

  defp retreive_public_key(params, config) do
    config = validate_cred(config)
    endpoint = "#{@endpoint}/get"

    make_request_with_cred(:post, endpoint, config, params)
    |> Utils.handle_resp(@endpoint)
  end

  defp validate_the_signature(jwt_string, jwk) do
    Joken.Signer.verify(jwt_string, Joken.Signer.create(jwk.key["alg"], jwk.key))
  end

  defp less_than_five_minutes_ago(iat) do
    with now <- DateTime.utc_now(),
         five_mins_ago <- DateTime.add(now, -300, :second),
         res when res in [:eq, :lt] <-
           DateTime.compare(five_mins_ago, DateTime.from_unix!(iat, :second)) do
      true
    else
      _ ->
        false
    end
  end

  defp bodies_match(body, body_sha256) do
    with hash <- :crypto.hash(:sha256, body),
         encoded <- Base.encode16(hash),
         ^body_sha256 <- String.downcase(encoded) do
      true
    else
      _ -> false
    end
  end

  defp create_event(body) do
    body = Jason.decode!(body)
    # type = body["webhook_type"]
    type_code = String.downcase("#{body["webhook_type"]}.#{body["webhook_code"]}")

    data =
      body
      |> Map.drop(["webhook_type"])
      |> Map.drop(["webhook_code"])

    {:ok, %Event{type: type_code, data: data}}
  end
end

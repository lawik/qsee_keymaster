defmodule QseeKeymaster do
  @moduledoc """
  Client for the Keymaster trusted application in Qualcomm's QSEE.

  On the Fairphone 3 the bootloader loads Keymaster 4 and leaves it
  resident in TrustZone, where it is the phone's only hardware-bound key
  store. This library speaks to it through a transport (see
  `QseeKeymaster.Transport`) and provides the pieces every request needs:
  command IDs (`QseeKeymaster.Command`), tags (`QseeKeymaster.Tag`) and
  the parameter-set wire format (`QseeKeymaster.ParamSet`).

  The utility commands the bootloader itself uses are public and verified
  against the phone: `version/1` and `date_support/1`. The request layout
  of the key operations is not public; `request/3` and `send/4` are the
  building blocks for them.

  Options accepted by every call: `:transport` (module or 2-arity
  function, default `QseeKeymaster.Transport.Device`), `:transport_opts`.
  """

  alias QseeKeymaster.{Command, Transport}

  @default_rsp_len 4096

  @doc """
  Keymaster's version: HAL major/minor and trusted application major/minor.

  Request is the command ID alone; the response is a signed status followed
  by four 32-bit version words. The Fairphone 3 answers HAL 4.0, TA 4.164.
  """
  def version(opts \\ []) do
    with {:ok,
          <<status::little-signed-32, major::little-32, minor::little-32, ta_major::little-32,
            ta_minor::little-32, _::binary>>} <-
           send(:get_version, <<>>, 64, opts) do
      if status == 0 do
        {:ok, %{major: major, minor: minor, ta_major: ta_major, ta_minor: ta_minor}}
      else
        {:error, {:keymaster, status}}
      end
    end
  end

  @doc "Whether the trusted application supports date tags. Response is a signed status."
  def date_support(opts \\ []) do
    with {:ok, <<status::little-signed-32, _::binary>>} <- send(:get_date_support, <<>>, 64, opts) do
      case status do
        0 -> {:ok, true}
        n -> {:error, {:keymaster, n}}
      end
    end
  end

  @doc "Build a request: the 32-bit command ID followed by `payload`."
  def request(command, payload \\ <<>>), do: <<Command.id(command)::little-32>> <> payload

  @doc """
  Send a command with a payload and return the raw response buffer.

  `rsp_len` is how large a response buffer to offer the application.
  """
  def send(command, payload \\ <<>>, rsp_len \\ @default_rsp_len, opts \\ []) do
    transport = Keyword.get(opts, :transport, Transport.Device)
    topts = Keyword.get(opts, :transport_opts, [])
    Transport.call(transport, request(command, payload), rsp_len, topts)
  end

  @doc "Interpret a response's leading signed 32-bit status."
  def status(<<status::little-signed-32, rest::binary>>), do: {status, rest}
end

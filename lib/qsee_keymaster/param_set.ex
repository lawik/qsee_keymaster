defmodule QseeKeymaster.ParamSet do
  @moduledoc """
  Keymaster parameter sets in AOSP's `AuthorizationSet` wire format.

  This is the serialization in `system/keymaster/android_keymaster/authorization_set.cpp`
  (Apache 2.0), which the vendor Keymaster client links in through
  `libkeymasterutils`. All integers are little-endian.

      <<indirect_size::32, indirect::binary-size(indirect_size),
        count::32, elements_size::32, elements::binary-size(elements_size)>>

  Each element is a tag word followed by its value: 32 bits for enums and
  uints, 64 for ulongs and dates, one byte for bools, and for byte strings
  a 32-bit length plus a 32-bit offset into the indirect data, which holds
  every byte-string value back to back in element order.

  A parameter is a `{tag, value}` tuple: `{:algorithm, :aes}`,
  `{:key_size, 256}`, `{:no_auth_required, true}`, `{:application_id, "x"}`.
  Enumerations accept atoms or integers.
  """

  alias QseeKeymaster.Tag

  @type param :: {Tag.name(), term()}

  @doc "Serialize a list of parameters."
  @spec encode([param()]) :: binary()
  def encode(params) do
    {elements, indirect} =
      Enum.reduce(params, {[], <<>>}, fn {tag, value}, {acc, indirect} ->
        word = Tag.encode(tag)

        case Tag.type(tag) do
          t when t in [:enum, :enum_rep] ->
            {[<<word::little-32, Tag.enum_value(tag, value)::little-32>> | acc], indirect}

          t when t in [:uint, :uint_rep] ->
            {[<<word::little-32, value::little-32>> | acc], indirect}

          t when t in [:ulong, :ulong_rep, :date] ->
            {[<<word::little-32, value::little-64>> | acc], indirect}

          :bool ->
            {[<<word::little-32, if(value, do: 1, else: 0)::8>> | acc], indirect}

          t when t in [:bytes, :bignum] ->
            offset = byte_size(indirect)

            {[<<word::little-32, byte_size(value)::little-32, offset::little-32>> | acc],
             indirect <> value}
        end
      end)

    elements = elements |> Enum.reverse() |> IO.iodata_to_binary()

    <<byte_size(indirect)::little-32, indirect::binary, length(params)::little-32,
      byte_size(elements)::little-32, elements::binary>>
  end

  @doc """
  Parse a serialized parameter set. Returns the parameters and whatever
  follows them in the binary.
  """
  @spec decode(binary()) :: {:ok, [param()], rest :: binary()} | {:error, term()}
  def decode(
        <<indirect_size::little-32, indirect::binary-size(indirect_size), count::little-32,
          elements_size::little-32, elements::binary-size(elements_size), rest::binary>>
      ) do
    with {:ok, params} <- decode_elements(elements, count, indirect, []) do
      {:ok, params, rest}
    end
  end

  def decode(_), do: {:error, :malformed}

  defp decode_elements(<<>>, 0, _indirect, acc), do: {:ok, Enum.reverse(acc)}
  defp decode_elements(_, 0, _indirect, _acc), do: {:error, :trailing_element_data}
  defp decode_elements(<<>>, _n, _indirect, _acc), do: {:error, :short_element_data}

  defp decode_elements(<<word::little-32, rest::binary>>, n, indirect, acc) do
    {name, type} = Tag.decode(word)

    case {type, rest} do
      {t, <<v::little-32, rest::binary>>} when t in [:enum, :enum_rep] ->
        decode_elements(rest, n - 1, indirect, [{name, Tag.enum_name(name, v)} | acc])

      {t, <<v::little-32, rest::binary>>} when t in [:uint, :uint_rep] ->
        decode_elements(rest, n - 1, indirect, [{name, v} | acc])

      {t, <<v::little-64, rest::binary>>} when t in [:ulong, :ulong_rep, :date] ->
        decode_elements(rest, n - 1, indirect, [{name, v} | acc])

      {:bool, <<v::8, rest::binary>>} when v in [0, 1] ->
        decode_elements(rest, n - 1, indirect, [{name, v == 1} | acc])

      {t, <<len::little-32, off::little-32, rest::binary>>} when t in [:bytes, :bignum] ->
        case indirect do
          <<_::binary-size(off), value::binary-size(len), _::binary>> ->
            decode_elements(rest, n - 1, indirect, [{name, value} | acc])

          _ ->
            {:error, {:bad_indirect_reference, name}}
        end

      _ ->
        {:error, {:malformed_element, name}}
    end
  end
end

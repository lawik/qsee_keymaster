defmodule QseeKeymaster.Tag do
  @moduledoc """
  Keymaster tags, their value types, and the enumerations they take.

  Numbers follow AOSP's `hardware/libhardware/include/hardware/keymaster_defs.h`
  (Apache 2.0). A tag is a 32-bit word: the top four bits give the value
  type, the low 28 bits the tag number. `encode/1` and `decode/1` move
  between the atom names used in this library and those words.
  """

  @types %{
    invalid: 0,
    enum: 1,
    enum_rep: 2,
    uint: 3,
    uint_rep: 4,
    ulong: 5,
    date: 6,
    bool: 7,
    bignum: 8,
    bytes: 9,
    ulong_rep: 10
  }

  @tags [
    {:purpose, :enum_rep, 1},
    {:algorithm, :enum, 2},
    {:key_size, :uint, 3},
    {:block_mode, :enum_rep, 4},
    {:digest, :enum_rep, 5},
    {:padding, :enum_rep, 6},
    {:caller_nonce, :bool, 7},
    {:min_mac_length, :uint, 8},
    {:kdf, :enum_rep, 9},
    {:ec_curve, :enum, 10},
    {:rsa_public_exponent, :ulong, 200},
    {:ecies_single_hash_mode, :bool, 201},
    {:include_unique_id, :bool, 202},
    {:blob_usage_requirements, :enum, 301},
    {:bootloader_only, :bool, 302},
    {:rollback_resistance, :bool, 303},
    {:early_boot_only, :bool, 305},
    {:active_datetime, :date, 400},
    {:origination_expire_datetime, :date, 401},
    {:usage_expire_datetime, :date, 402},
    {:min_seconds_between_ops, :uint, 403},
    {:max_uses_per_boot, :uint, 404},
    {:all_users, :bool, 500},
    {:user_id, :uint, 501},
    {:user_secure_id, :ulong_rep, 502},
    {:no_auth_required, :bool, 503},
    {:user_auth_type, :enum, 504},
    {:auth_timeout, :uint, 505},
    {:allow_while_on_body, :bool, 506},
    {:trusted_confirmation_required, :bool, 508},
    {:unlocked_device_required, :bool, 509},
    {:all_applications, :bool, 600},
    {:application_id, :bytes, 601},
    {:exportable, :bool, 602},
    {:application_data, :bytes, 700},
    {:creation_datetime, :date, 701},
    {:origin, :enum, 702},
    {:rollback_resistant, :bool, 703},
    {:root_of_trust, :bytes, 704},
    {:os_version, :uint, 705},
    {:os_patchlevel, :uint, 706},
    {:unique_id, :bytes, 707},
    {:attestation_challenge, :bytes, 708},
    {:attestation_application_id, :bytes, 709},
    {:attestation_id_brand, :bytes, 710},
    {:attestation_id_device, :bytes, 711},
    {:attestation_id_product, :bytes, 712},
    {:attestation_id_serial, :bytes, 713},
    {:attestation_id_imei, :bytes, 714},
    {:attestation_id_meid, :bytes, 715},
    {:attestation_id_manufacturer, :bytes, 716},
    {:attestation_id_model, :bytes, 717},
    {:vendor_patchlevel, :uint, 718},
    {:boot_patchlevel, :uint, 719},
    {:device_unique_attestation, :bool, 720},
    {:identity_credential_key, :bool, 721},
    {:associated_data, :bytes, 1000},
    {:nonce, :bytes, 1001},
    {:auth_token, :bytes, 1002},
    {:mac_length, :uint, 1003},
    {:reset_since_id_rotation, :bool, 1004},
    {:confirmation_token, :bytes, 1005}
  ]

  @enums %{
    algorithm: %{rsa: 1, ec: 3, aes: 32, triple_des: 33, hmac: 128},
    purpose: %{encrypt: 0, decrypt: 1, sign: 2, verify: 3, derive_key: 4, wrap: 5},
    block_mode: %{ecb: 1, cbc: 2, ctr: 3, gcm: 32},
    padding: %{
      none: 1,
      rsa_oaep: 2,
      rsa_pss: 3,
      rsa_pkcs1_1_5_encrypt: 4,
      rsa_pkcs1_1_5_sign: 5,
      pkcs7: 64
    },
    digest: %{none: 0, md5: 1, sha1: 2, sha_2_224: 3, sha_2_256: 4, sha_2_384: 5, sha_2_512: 6},
    ec_curve: %{p_224: 0, p_256: 1, p_384: 2, p_521: 3},
    origin: %{generated: 0, derived: 1, imported: 2, unknown: 3, securely_imported: 4},
    blob_usage_requirements: %{standalone: 0, requires_file_system: 1},
    user_auth_type: %{none: 0, password: 1, fingerprint: 2, any: 0xFFFFFFFF},
    kdf: %{
      none: 0,
      rfc5869_sha256: 1,
      iso18033_2_kdf1_sha1: 2,
      iso18033_2_kdf1_sha256: 3,
      iso18033_2_kdf2_sha1: 4,
      iso18033_2_kdf2_sha256: 5
    }
  }

  @key_formats %{x509: 0, pkcs8: 1, raw: 3}
  @security_levels %{software: 0, trusted_environment: 1, strongbox: 2}

  @type name :: atom()
  @type type ::
          :invalid
          | :enum
          | :enum_rep
          | :uint
          | :uint_rep
          | :ulong
          | :date
          | :bool
          | :bignum
          | :bytes
          | :ulong_rep

  @by_name Map.new(@tags, fn {name, type, num} -> {name, {type, num}} end)
  @by_word Map.new(@tags, fn {name, type, num} ->
             {Bitwise.bor(Bitwise.bsl(@types[type], 28), num), {name, type}}
           end)

  @doc "All known tags as `{name, type, number}`."
  def all, do: @tags

  @doc "The value type of a tag name."
  @spec type(name()) :: type()
  def type(name), do: @by_name |> Map.fetch!(name) |> elem(0)

  @doc "The 32-bit tag word for a tag name."
  @spec encode(name()) :: non_neg_integer()
  def encode(name) do
    {type, num} = Map.fetch!(@by_name, name)
    Bitwise.bor(Bitwise.bsl(@types[type], 28), num)
  end

  @doc """
  The name and type of a 32-bit tag word. Unknown tags decode to
  `{{:unknown, number}, type}` so a response with a tag this library doesn't
  know is still readable.
  """
  @spec decode(non_neg_integer()) :: {name() | {:unknown, non_neg_integer()}, type()}
  def decode(word) do
    case Map.fetch(@by_word, word) do
      {:ok, found} -> found
      :error -> {{:unknown, Bitwise.band(word, 0x0FFFFFFF)}, type_of_word(word)}
    end
  end

  @doc "The value type encoded in the top four bits of a tag word."
  def type_of_word(word) do
    code = Bitwise.bsr(word, 28)
    Enum.find_value(@types, :invalid, fn {t, c} -> if c == code, do: t end)
  end

  @doc "Encode an enumeration value (atom or integer) for a tag."
  def enum_value(_tag, value) when is_integer(value), do: value

  def enum_value(tag, value) when is_atom(value) do
    Map.fetch!(Map.fetch!(@enums, tag), value)
  end

  @doc "Decode an enumeration value for a tag back to its atom, or leave the integer."
  def enum_name(tag, value) do
    case Map.fetch(@enums, tag) do
      {:ok, table} -> Enum.find_value(table, value, fn {k, v} -> if v == value, do: k end)
      :error -> value
    end
  end

  def key_format(name) when is_atom(name), do: Map.fetch!(@key_formats, name)
  def key_format(n) when is_integer(n), do: n
  def security_level(name) when is_atom(name), do: Map.fetch!(@security_levels, name)
  def security_level(n) when is_integer(n), do: n
end

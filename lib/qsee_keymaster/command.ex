defmodule QseeKeymaster.Command do
  @moduledoc """
  Command IDs of Qualcomm's Keymaster trusted application.

  From the bootloader's `include/km_main.h` in LK (Apache 2.0): key
  operations live at `0x100 + n`, the utility commands the bootloader uses
  at `0x200 + n`. Every request starts with the 32-bit command ID.
  """

  @key_ops %{
    get_supported_algorithms: 0x101,
    get_supported_block_modes: 0x102,
    get_supported_padding_modes: 0x103,
    get_supported_digests: 0x104,
    get_supported_import_formats: 0x105,
    get_supported_export_formats: 0x106,
    add_rng_entropy: 0x107,
    generate_key: 0x108,
    get_key_characteristics: 0x109,
    rescope: 0x10A,
    import_key: 0x10B,
    export_key: 0x10C,
    delete_key: 0x10D,
    delete_all_keys: 0x10E,
    begin: 0x10F,
    get_output_size: 0x110,
    update: 0x111,
    finish: 0x112,
    abort: 0x113
  }

  @utils %{
    get_version: 0x200,
    set_rot: 0x201,
    read_lk_device_state: 0x202,
    write_lk_device_state: 0x203,
    milestone_call: 0x204,
    secure_write_protect: 0x206,
    set_boot_state: 0x208,
    set_vbh: 0x211,
    get_date_support: 0x215
  }

  @all Map.merge(@key_ops, @utils)

  def all, do: @all
  def key_ops, do: @key_ops
  def utils, do: @utils

  @doc "Numeric ID of a command, given its atom or an integer."
  def id(n) when is_integer(n), do: n
  def id(name) when is_atom(name), do: Map.fetch!(@all, name)

  @doc "Name of a command ID, or the integer if unknown."
  def name(n), do: Enum.find_value(@all, n, fn {k, v} -> if v == n, do: k end)
end

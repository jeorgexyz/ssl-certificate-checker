# Renders terminal-style SVG screenshots of the CLI for the README.
#
# Run from the project root, with network access:
#
#     MIX_ENV=prod mix escript.build
#     elixir scripts/render_cli_screenshots.exs
#
# The images show live certificates, so regenerating them changes dates and serial numbers.

defmodule CliScreenshots do
  @screenshots [
    {"github.com", "docs/images/cli-valid.svg"},
    {"expired.badssl.com", "docs/images/cli-invalid.svg"}
  ]

  @font_size 13
  @line_height 18
  @char_width 7.8
  @padding 20
  @title_bar_height 36

  def run do
    captures = for {host, path} <- @screenshots, do: {host, path, capture(host)}
    all_lines = Enum.flat_map(captures, fn {_host, _path, lines} -> lines end)
    columns = all_lines |> Enum.map(&String.length/1) |> Enum.max()
    rows = captures |> Enum.map(fn {_host, _path, lines} -> length(lines) end) |> Enum.max()

    # Every screenshot gets the same size so they line up side by side.
    for {host, path, lines} <- captures do
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, render(host, lines, columns, rows))
      IO.puts("Wrote #{path}")
    end
  end

  defp capture(host) do
    {output, exit_code} =
      System.cmd("escript", ["ssl_certificate_checker", host], stderr_to_stdout: true)

    body = output |> String.trim_trailing() |> String.split(~r/\r?\n/)

    ["$ ssl_certificate_checker #{host}"] ++
      body ++ ["", "$ echo $?", Integer.to_string(exit_code)]
  end

  defp render(host, lines, columns, rows) do
    width = round(@padding * 2 + columns * @char_width)
    height = @title_bar_height + rows * @line_height + @padding

    text_rows =
      lines
      |> Enum.with_index()
      |> Enum.map_join("\n", fn {line, index} ->
        y = @title_bar_height + @font_size + index * @line_height

        spans =
          Enum.map_join(segments(line), fn {text, class} ->
            ~s(<tspan class="#{class}">#{escape(text)}</tspan>)
          end)

        ~s(  <text x="#{@padding}" y="#{y}">#{spans}</text>)
      end)

    """
    <svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" width="#{width}" height="#{height}" viewBox="0 0 #{width} #{height}" role="img" aria-labelledby="title">
      <title id="title">ssl_certificate_checker output for #{escape(host)}</title>
      <style>
        text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size: #{@font_size}px; white-space: pre; fill: #c9d1d9; }
        .prompt { fill: #7ee787; }
        .command, .heading { fill: #f0f6fc; font-weight: 600; }
        .label { fill: #8b949e; }
        .dim { fill: #6e7681; }
        .ok { fill: #3fb950; font-weight: 600; }
        .bad { fill: #f85149; font-weight: 600; }
        .warn { fill: #d29922; font-weight: 600; }
        .window-title { fill: #8b949e; font-size: 12px; }
      </style>
      <rect x="0.5" y="0.5" width="#{width - 1}" height="#{height - 1}" rx="8" fill="#0d1117" stroke="#30363d"/>
      <circle cx="20" cy="18" r="6" fill="#ff5f57"/>
      <circle cx="40" cy="18" r="6" fill="#febc2e"/>
      <circle cx="60" cy="18" r="6" fill="#28c840"/>
      <text class="window-title" x="#{div(width, 2)}" y="22" text-anchor="middle">#{escape(host)}</text>
    #{text_rows}
    </svg>
    """
  end

  defp segments("$ " <> command), do: [{"$ ", "prompt"}, {command, "command"}]
  defp segments("SSL Certificate Information" = line), do: [{line, "heading"}]
  defp segments("Subject Alternative Names:" = line), do: [{line, "heading"}]
  defp segments("Checking " <> _ = line), do: [{line, "dim"}]
  defp segments("=" <> _ = line), do: [{line, "dim"}]
  defp segments("  - Certificate " <> _ = line), do: [{line, "bad"}]
  defp segments("  - Verification " <> _ = line), do: [{line, "bad"}]
  defp segments("0"), do: [{"0", "ok"}]

  defp segments(line) do
    cond do
      Regex.match?(~r/^\d+$/, line) ->
        [{line, "bad"}]

      match = Regex.run(~r/^([A-Z][A-Za-z ]+:\s+)(.+)$/, line) ->
        [_line, label, value] = match
        [{label, "label"}, {value, value_class(label, value)}]

      true ->
        [{line, "value"}]
    end
  end

  defp value_class("Status:" <> _, "Valid"), do: "ok"
  defp value_class("Status:" <> _, _value), do: "bad"
  defp value_class("Expiry:" <> _, "OK" <> _), do: "ok"
  defp value_class("Expiry:" <> _, "EXPIRED" <> _), do: "bad"
  defp value_class("Expiry:" <> _, _value), do: "warn"
  defp value_class(_label, _value), do: "value"

  defp escape(text) do
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end
end

CliScreenshots.run()

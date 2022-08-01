# Test Minidumps and Symbols

Much of this data is from random people generating things on their machines and checking
in the artifacts, making the data impossible to regenerate/reproduce. In general it's
always going to be difficult/impossible to perfectly reproduce things because so much
relies on huge piles of toolchains. We're working on improving this situations with
[minidump-pipeline][].

The following are derived from [minidump-pipeline][] and can theoretically be regenerated
with new/different toolchains if desired:

* `pipeline-inlines-macos-segv.dmp`
    * `symbols/crash-client/509C0610949836F7B70BD88BCF03E5400/crash-client.sym`
    * generated to test the new .sym inlinee info (using pipeline-inlines)
    * generated on x64 macos




[minidump-pipeline]: https://github.com/Gankra/minidump-pipeline
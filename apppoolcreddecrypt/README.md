## Info

A POC to show how IIS App Pool credentials are decrypted without appcmd.exe.

This requires Administrator or SYSTEM privileges to run on the target host.

## Usage

Grab the App Pool creds from the file in:

```
C:\Windows\System32\inetsrv\Config\applicationHost.config
```

Creds can be found looking like this:

```
[enc:IISWASOnlyCngProvider:SmJ33J7NRBTOyBpvZfTHUDz01YxQbBSkbw19BG58+3cP8njbpi5xBtfaO9vaMEOmm54+2SjGeWsI9NmYFp8/ZAPSYW8lwoRpWs3OVzwPCDU=:enc]
```

Then run the script:

```
AppPoolCredDecrypt.exe "SmJ33J7NRBTOyBpvZfTHUDz01YxQbBSkbw19BG58+3cP8njbpi5xBtfaO9vaMEOmm54+2SjGeWsI9NmYFp8/ZAPSYW8lwoRpWs3OVzwPCDU="
```
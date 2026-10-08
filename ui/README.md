# port1897 app window

The Windows app: an Electron window styled after the Rethink Android app's home
screen. It starts the engine (`fswin.exe`, built from `../cmd/fswin`) through a
UAC prompt and talks to it over its loopback control API.

## Run from source

1. Build the engine and put it with Wintun in `engine/`:

   ```powershell
   cd ..
   $env:GOOS="windows"; go build -ldflags=-checklinkname=0 -o ui\engine\fswin.exe .\cmd\fswin
   # copy wintun.dll (from wintun.net, bin\amd64) into ui\engine\
   ```

2. `npm install`, then `npm start`.

`npm run dist` builds an installer and a portable `.exe` into `dist/`.
GitHub Actions does all of this on every push (the **App** workflow).

Opening `renderer/index.html` in a browser shows the screens in a demo mode
with sample data.

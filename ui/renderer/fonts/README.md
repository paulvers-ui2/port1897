# Flag font

Windows' emoji font has no country flags: a flag emoji such as 🇺🇸 shows as
the letters "US". `TwemojiCountryFlags.woff2` holds only the flags, so the
Logs screen can show them (`.flag` in `components.css`).

- Source: npm package [country-flag-emoji-polyfill](https://github.com/talkjs/country-flag-emoji-polyfill)
  0.1.10, `dist/TwemojiCountryFlags.woff2`, from cdn.jsdelivr.net.
- sha256: `9f04f14429bb6a9f415c7a4dd902a918d7e81a4f7526c415496fdb063954e3b8`
  (78,292 bytes).
- License (`TwemojiCountryFlags-LICENSE.md`): the font build is MIT,
  © 2022 TalkJS; the flag art is [Twemoji](https://github.com/twitter/twemoji),
  CC BY 4.0.

It ships inside the app; nothing is fetched at runtime.

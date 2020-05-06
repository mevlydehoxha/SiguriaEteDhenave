# SiguriaEteDhenave
Komanda create-user.
Output:
<code>$ java ds create-user keys1
Eshte krijuar celsi privat 'keys/keys1.xml'
Eshte krijuar celsi publik 'keys/keys1.pub.xml'
</code>
<code>$ java ds create-user keys2
Eshte krijuar celsi privat 'keys/keys2.xml'
Eshte krijuar celsi publik 'keys/keys2.pub.xml'
</code>
<code>$ java ds create-user keys1
Gabim:Celesi 'keys1' ekziston paraprakisht.
</code>

Komanda delete-user.
Output:
<code>$ java ds delete-user keys1
Eshte larguar celesi privat 'keys/keys1.xml'
Eshte larguar celesi publik 'keys/keys1.pub.xml'
</code>
<code>$ java ds delete-user keys1
Gabim:Celesi 'keys1' nuk ekziston.
</code>
<code>$ java ds delete-user keys2
Eshte larguar celesi privat 'keys/keys2.xml'
</code>

Komanda export-key.
Output:
<code>$ java ds export-key public keys

<RSAKeyValue>
  <Modulus>ANUnKqVVD8GXav8xewsbSJq97w7bSwGCl7uMpx96Foe0ECu+iUwfCBwwj6vL/p77+Lfl0J+r/Dy4wgh1CbnLCT2OC1x1BZHc9xHdmutR2KdOO0i8pWOzVvc3oNEh2W/7Fit+ro9l+akWoJzhjWqUhHxxtZfidtqmUuwmWeiP0UWgDwqs78/QQDKJQDBM9awVI+T8prCB6jo53JhFAmwEzF2/Oo3Z1klKQRpQAvCmuocMbMOUEBzmoI7aTxOW4dbeS5tqz00+3Gu/UTbOtpYCUz72MD7sp9yQ65UnAVCIPeQophSGnEIwIVzFvdgSr/ctnGrgQm2NyjJFk04wQPPDn7E=</Modulus>
  <Exponent>AQAB</Exponent>
</RSAKeyValue>
</code>

<code>$ java ds export-key private keys

<RSAKeyValue>
  <Modulus>AJgmsuPvhk4qWFOP6gAgNmeHSWH01FhCtRoVqWnr5ayY3Y+0F+iM0D26O7LqF8NGQyvJmtQV2E6PjrEXzYLMYmvr9x8ihkAoc5uKjZYhCYLnqD1BKpW+civoclSBgOAluT0lkKqpHz3xypwZUOFXQ3IeuvgmCFGc1dRWP/WkPSR1kjTCpuhbKxj8+WWcrjz/HOVgmxmAs5rJWK32fDxTS6mD1M8x5n+rSv49tnSzlZuNSVwf41nB+4yp/KkMPU4FZlDUfF70HAwbUR2iR+1vUxPwdmINz+S2CqXHkxpyfU7w+sxc3rqXKupUG3aVGHvHbAtk9XVjZb+lWG49/PxriLM=</Modulus>
  <Exponent>AQAB</Exponent>
  <P>ANFnygry6DXbgRlzh12TA2lfoOR/J3j034xHCDenZFlAKWSNFMyuBFL1ypyELoeWm0XorFn++mXnS/qf0O8y3GUcofXxFuVQGeaHtY0/OqneWJRKI6vIeA+5p9n06XcW/I9qZCDERlTaPXsraq5r3p2X/EqS2LQWpl53bVpN5B/N</P>
  <Q>ALoBk4reiDsqUokduO2QSmEoBPLsxmNsR43cWENNtpZV99HPDNsNtyZ0WgGKAx6tnxo+9p98ms6083mCIHn8s4KuZMi5suJMSMVIuDeKu9X4pAmLXc/GNXU/amNDiGokEg0Fglxp/pJroJFoyG1y5aaJfBVCTDcpWGmmRiJ7yMp/</Q>
  <DP>ALJcUfZDcdA1199izMDCMJy3LCaTu35GLIaiFfi5Zjqy8M7JcBbqfZpf6qSn3a31dOn1xZ+eE49qlAezylWDH8ArxDPkltjZAkad/uCBI6l+Tjp4b6uow8K5IqP9/EFIXfSV7RUPuMwbW1Sm5WYNUP8wbl7idxvlUu2RkZ3iTFVd</DP>
  <DQ>AJYAPW7JBM3J1KOU35RdP05Yip0pCtgU8yNY5ajpG+ziySZetfxVdDTDse350YhE9cChtBtrziASVyLPKMeXXWBuqQIilzrdz/WhLkZEUDQ+/nJf/LhZHLU//ditFm6aRiBQKA/EvrJvrx50hOWWudJynyk5vOLjKdSRbY/TiVqb</DQ>
  <InverseQ>RKydY7lW+ULvGI0j8xKhzRYbHdgkcvI6HGvv7FwzE159nCUNqtGjE0k2k+xaUxGg9lo5G3cE4rjH0ie+ZzQfFYc+GaUQHctFhXzLV85AWbAOg4+wlnryTs6aO3Uu5o0iKl0KV9Zz4buvsi8L0oqRalbWQM4k7FmRaoTqVfdccFs=</InverseQ>
  <D>KZsDdgLspfk8V/VVlp04Y00CSxAI9O2g2jYsMnO4RV8zzvT/SK8gzpBbfMw4nURcX9/sP6yNjsYAzfplTywWic5nsBLfxTGKk3Dq0K/OCwbP4ZgtTe9bBxi0Etmq5SBLrCXWjmRaz7SLo+3kSQp0vgMbO3oi8jZB3qOLL9+ufIZhyUKkzrB3G4BFZyKwUrlDfa/xjEhIJFFyarEkPlZyDzb7fxllIG020Rmfq4BCc42PibPSu9dguyNWnCNA9+dHJs2g32Bn4HkMcrU2Wv/SO6uufphtA22nKBgaGQfzphhTl1Mjz5w7NQC3hz4mNsVDJ9ty+vO6yadBdVS6Q6YOaQ==</D>
</RSAKeyValue>
</code>

<code>$ java ds export-key public keys celesi.xml

Celsi publik u ruajt ne fajllin 'celesi.xml'
</code>
<code>$ java ds export-key public filan
Gabim:Celesi publik 'filan' nuk ekziston.
</code>


Komanda import-key.
Output:
<code>$ java ds import-key file1 keys.xml
Celesi publik u ruajt ne fajllin 'keys/file1.pub.xml'
Celesi privat u ruajt ne fajllin 'keys/file1.xml'
</code>

<code>$ java ds import-key file2 keys.pub.xml
Celesi publik u ruajt ne fajllin 'keys/file2.pub.xml'
</code>

<code>$ java ds import-key file1 keys.xml
Gabim:Celesi 'file1' ekziston paraprakisht.
</code>

<code>$ java ds import-key file3 keys.png
Gabim:Fajlli i dhene nuk eshte celes valid.
</code>



Komanda write-message.
Output:
<code>$ java ds write-message keys "Takimi mbahet te premten ne ora 11:00"
VGFraW1pIG1iYWhldCB0ZSBwcmVtdGVuIG5lIG9yYSAxMTowMA==.DY+vRNHD59WtLy0QC3iQnPcKb/mfqhApgTwm6kRJ4bjsrtVabkhfMQp8UUXPLi4i.N5h3u8l2YdJ4mh1chGpwS8RgiOe3SkFl1T/2FV/o0/5FwjM06KXiJ7EVMJKL+qZNlYO/RKFI4f/peJOhZ3vCg1BybBGHyyyQ6YN8YFl/AAMnS3OTPVl44Gc0tHJStuz87BLKWwVcqKGkcvCq/O/dDPKdK6xsdm9V0LuKYMb+MsASoABDecfPCHAMwR/KkNhxVPrPA5PVzNRK+8lNZflB6eYwSMBHG9QF9qOuYI6fPi9DuaN1XFs2ipNSIqwElG3jNyFIixLADtd6j1jbLYnrh82/KHAFVbQwDpzPv3r03+bH9D+Mvz1sVj+sEFyGAmPOU4af1Z8ciV8+Z5xVmSLMyg==.6rATli3QokeFZbKYh6w1z8RspdQJps3MeDVgPQdj0ekMgF4ENea+KQ==
</code>

<code>
  $ java ds write-message keys1 "Pershendetje" ciphertext.txt
Mesazhi i enkriptuar u ruajt ne fajllin 'ciphertext.txt'
</code>

<code>$ java ds write-message keys2 "Pershendetje"
Gabim: Celesi publik 'keys2' nuk ekziston.
</code>




Komanda read-message.
Output:
<code>$ java ds read-message VGFraW1pIG1iYWhldCB0ZSBwcmVtdGVuIG5lIG9yYSAxMTowMA==.DY+vRNHD59WtLy0QC3iQnPcKb/mfqhApgTwm6kRJ4bjsrtVabkhfMQp8UUXPLi4i.N5h3u8l2YdJ4mh1chGpwS8RgiOe3SkFl1T/2FV/o0/5FwjM06KXiJ7EVMJKL+qZNlYO/RKFI4f/peJOhZ3vCg1BybBGHyyyQ6YN8YFl/AAMnS3OTPVl44Gc0tHJStuz87BLKWwVcqKGkcvCq/O/dDPKdK6xsdm9V0LuKYMb+MsASoABDecfPCHAMwR/KkNhxVPrPA5PVzNRK+8lNZflB6eYwSMBHG9QF9qOuYI6fPi9DuaN1XFs2ipNSIqwElG3jNyFIixLADtd6j1jbLYnrh82/KHAFVbQwDpzPv3r03+bH9D+Mvz1sVj+sEFyGAmPOU4af1Z8ciV8+Z5xVmSLMyg==.6rATli3QokeFZbKYh6w1z8RspdQJps3MeDVgPQdj0ekMgF4ENea+KQ==
Marresi:
Mesazhi:Takimi mbahet te premten ne ora 11:00
</code>

<code>
  $ java ds read-message VGFraW1pIG1iYWhldCB0ZSBwcmVtdGVuIG5lIG9yYSAxMTowMA==.DY+vRNHD59WtLy0QC3iQnPcKb/mfqhApgTwm6kRJ4bjsrtVabkhfMQp8UUXPLi4i.N5h3u8l2YdJ4mh1chGpwS8RgiOe3SkFl1T/2FV/o0/5FwjM06KXiJ7EVMJKL+qZNlYO/RKFI4f/peJOhZ3vCg1BybBGHyyyQ6YN8YFl/AAMnS3OTPVl44Gc0tHJStuz87BLKWwVcqKGkcvCq/O/dDPKdK6xsdm9V0LuKYMb+MsASoABDecfPCHAMwR/KkNhxVPrPA5PVzNRK+8lNZflB6eYwSMBHG9QF9qOuYI6fPi9DuaN1XFs2ipNSIqwElG3jNyFIixLADtd6j1jbLYnrh82/KHAFVbQwDpzPv3r03+bH9D+Mvz1sVj+sEFyGAmPOU4af1Z8ciV8+Z5xVmSLMyg==.6rATli3QokeFZbKYh6w1z8RspdQJps3MeDVgPQdj0ekMgF4ENea+KQ==
Gabim: Celesi privat 'keys/privatekey.xml' nuk ekziston.

</code>

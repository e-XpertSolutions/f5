when CLIENT_ACCEPTED {
  set cookiename "PS_TOKEN"
  set encryption_passphrase "hEuoYjmFUpB4PcpO3bUdQtLP4ic7jjmD5UB5KOifo5U8BClQfvotmu9LEa949nz"
}
when HTTP_RESPONSE {
  if { [HTTP::cookie exists $cookiename] } {
    HTTP::cookie encrypt $cookiename $encryption_passphrase
  }
}
when HTTP_REQUEST {
  if { [HTTP::cookie exists $cookiename] } {
    set decrypted [HTTP::cookie decrypt $cookiename $encryption_passphrase]
    if { ($decrypted eq "") } {
      # Cookie wasn't encrypted, delete it
      HTTP::cookie remove $cookiename
    }
  }
}
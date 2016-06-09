when RULE_INIT {
  set cookieToken "PS_TOKEN"
  # to be changed prior to any publishing
  set passphrase "hEuoYjmFUpB4PcpO3bUdQtLP4ic7jjm"
}
when HTTP_RESPONSE {
  if { [HTTP::cookie exists $cookieToken ] } {
    HTTP::cookie encrypt $cookieToken $passphrase
  }
}
when HTTP_REQUEST {
  if { [HTTP::cookie exists $cookieToken ] } {
    set decrypted [HTTP::cookie decrypt $cookieToken $passphrase]
    if { ($decrypted eq "") } {
      # Cookie wasn't encrypted, delete it
      HTTP::cookie remove $cookieToken 
    }
  }
}
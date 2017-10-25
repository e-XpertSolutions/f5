when HTTP_REQUEST {
    # Detect the origin SP from the initial SAML Auth Req
    if {[HTTP::path] eq "/saml/idp/profile/redirectorpost/sso" && [HTTP::method] eq "POST"} {
        set spName "NULL"
        set referer [HTTP::header Referer]
        if { !([URI::host $referer] eq "ssotest.example.net") } {
            set spName [URI::host $referer]
            # If the session is already created, set the session variable (does not work for the very first auth)
            ACCESS::session data set session.custom.saml.spName $spName
        }
    }
}

# For the first authentication SAML Auth req, the session does not exist yet.
# So the session variable with the SP name must be created here
# The var "spName" is set previously while the HTTP_REQUEST event

when ACCESS_SESSION_STARTED {
    if { [info exists spName] } {
        ACCESS::session data set session.custom.saml.spName $spName
    }
}

when ACCESS_ACL_ALLOWED {
    # Just in case we are not in a standard SAML Auth (for example the user tried to login directly to the IDP)
    # Display a static page saying login is OK
    if { [HTTP::uri] != "/saml/idp/profile/redirectorpost/sso" } {
        ACCESS::respond 200 content "<html><body>You are now connected</body></html>" Connection Close
    } else {
        # Here the SP should be known, select the proper IDP config
        set savedSpName [ACCESS::session data get session.custom.saml.spName]
        set idp [class match -value [string tolower $savedSpName] equals dg-test-saml-idp-selector]
        # Test if we have a configuration IDP for the SP
        # If we dont have any, the default SSO profile of the AP will be used
        if { [info exists idp] && $idp != ""} {
            set idp_config /Common/$idp
            # log local0. "IDP $idp_config select for [HTTP::uri]"
            WEBSSO::select $idp_config
            unset idp_config
        }
    }
}

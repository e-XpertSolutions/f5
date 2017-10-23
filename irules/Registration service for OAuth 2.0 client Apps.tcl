when RULE_INIT {

  ###
  # credentials required to access iControl REST API
  ###

  set static::adm_user "admin"
  set static::adm_pwd "admin"

  ###
  # settings required to authenticate the user trying to register an application
  ###

  set static::timeout 300
  set static::lifetime 300
  set static::access_profile "/Common/ap-ldap-auth"

  ###
  # settings required to update the APM configuration with the newly created ClientApp configuraiton
  ###

  set static::adm_partition "Common"
  set static::oauth_profile "my-oauth-profile"
  set static::scopes "myscope"

  ###
  # settings required to sync the OAuth 2.0 Authorization Server access profile
  ###

  set static::oauth_access_policy "ap-oauth-auth-server"

  ###
  # settings required to publish the client registration service
  ###

  set static::client_register_uri "/f5-oauth2/v1/client-register"
  set static::host "oauthas.example.com"

}

when CLIENT_ACCEPTED {
  ###
  # When we accept a connection, create an Access session and save the session ID.
  ###

  set flow_sid [ACCESS::session create -timeout $static::timeout -lifetime $static::lifetime]
}

when HTTP_REQUEST {

  ###
  # initialize vars
  ###

  set username ""
  set password ""
  set name ""
  set client_app ""
  set scopes ""
  set client_id ""
  set client_secret ""
  set agent ""

  set timestamp [clock seconds]

  switch -glob [string tolower [HTTP::header "User-Agent"]] {
    "*android*" { set agent "android" }
    "*ios*" { set agent "ios" }
    default { set agent "default" }
  }

  ###
  # identify client registration request. The client applicaiton needs to do a POST request on client registration URI and provides username and password
  ###

  if { [HTTP::path] eq $static::client_register_uri and [HTTP::host] eq $static::host and [HTTP::method] eq "POST" } {

    set username [URI::query "/?[HTTP::payload]" username]
    set password [URI::query "/?[HTTP::payload]" password]

    ###
    # play inline ACCESS policy to validate user credentials
    ###

    set username [string map -nocase { "%40" "@" } $username]

    ACCESS::policy evaluate -sid $flow_sid -profile $static::access_profile session.logon.last.username $username session.logon.last.password $password session.server.landinguri [string tolower [HTTP::path]]

    if { [ACCESS::policy result -sid $flow_sid] eq "deny" or [ACCESS::policy result -sid $flow_sid] eq "not_started" } {
      HTTP::respond 403 content "{\"error\": \"Invalid user credentials\",\"error-message\": \"Access denied by Acces policy\"}" noserver Content-Type "application/json" Connection Close
      ACCESS::session remove -sid $flow_sid
      event disable all
    }

    ACCESS::session remove -sid $flow_sid

    ###
    # start transaction (transId, state) state = STARTED
    ###

    # POST /mgmt/tm/transaction

    set json_body "{}"
    set status [call /Common/HSSR::http_req -state hstate -uri "http://127.0.0.1:8100/mgmt/tm/transaction" -method POST -body $json_body -type "application/json; charset=utf-8" -rbody rbody -userid $static::adm_user -passwd $static::adm_pwd]
    set json_result [call /Common/sys-exec::json2dict $rbody]

    if { $status contains "200" } {
      set state [lindex $json_result 3]
      set trans_id [lindex $json_result 1]

      if { $state contains "STARTED" } {
        HTTP::respond 403 content "{\"error\": \"Transaction failed\",\"error-message\": \"[lindex $json_result 3]\"}" noserver Content-Type "application/json" Connection Close
        event disable all
      }
      } else {
        HTTP::respond 403 content "{\"error\": \"Transaction failed\",\"error-message\": \"[lindex $json_result 3]\"}" noserver Content-Type "application/json" Connection Close
        event disable all
      }

      ###
      # generate client name and client application name
      ###

      set username [string map -nocase { "@" "." } $username]

      set name "$username-$agent-$timestamp"
      set client_app $name
      set scopes $static::scopes

      ###
      #   prepare and execute API REST call to create a new client application. Endpoint: /mgmt/tm/apm/oauth/oauth-client-app
      ###

      set json_body "{\"name\": \"$name\",\"appName\": \"$client_app\",\"authType\": \"secret\",\"grantPassword\": \"enabled\",\"scopes\": \"$scopes\"}"
      set status [call /Common/HSSR::http_req -state hstate -uri "http://127.0.0.1:8100/mgmt/tm/apm/oauth/oauth-client-app" -method POST -body $json_body -type "application/json; charset=utf-8" -rbody rbody -userid $static::adm_user -passwd $static::adm_pwd -headers { X-F5-REST-Coordination-Id $trans_id } ]
      set json_result [call /Common/sys-exec::json2dict $rbody]

      if { $status contains "200" } {

        ###
        # extract client_id and client_secret from JSON body
        ###

        set client_id [lindex $json_result 21]
        set client_secret [lindex $json_result 23]

        ###
        # prepare and execute API REST call to bind the client application to the OAuth profile. Endpoint: /mgmt/tm/apm/profile/oauth/~$static::adm_parition~$static::oauth_profile/client-apps
        ###

        set json_body "{\"name\": \"$name\"}"
        set status [call /Common/HSSR::http_req -state hstate -uri "http://127.0.0.1:8100/mgmt/tm/apm/profile/oauth/~$static::adm_partition~$static::oauth_profile/client-apps" -method POST -body $json_body  -type "application/json; charset=utf-8" -rbody rbody -userid $static::adm_user -passwd $static::adm_pwd -headers { X-F5-REST-Coordination-Id $trans_id } ]
        set json_result [call /Common/sys-exec::json2dict $rbody]

        ###
        # if binding is successful, respond to the client with client_id and client_secret
        ###

        if { $status contains "200" } {

          ###
          # Prepare and execute API REST call to apply Access Profile after Client Application has been assigned to OAuth profile
          ###

          set json_body "{\"generationAction\": \"increment\"}"
          set status [call /Common/HSSR::http_req -state hstate -uri "http://127.0.0.1:8100/mgmt/tm/apm/profile/access/~$static::adm_partition~$static::oauth_access_policy" -method PATCH -body $json_body  -type "application/json; charset=utf-8" -rbody rbody -userid $static::adm_user -passwd $static::adm_pwd -headers { X-F5-REST-Coordination-Id $trans_id } ]
          set json_result [call /Common/sys-exec::json2dict $rbody]

          if { $status contains "200" } {
            ###
            # Commit transaction
            ###

            set json_body "{\"state\": \"VALIDATING\"}"
            set status [call /Common/HSSR::http_req -state hstate -uri "http://127.0.0.1:8100/mgmt/tm/transaction/$trans_id" -method PATCH -body $json_body -type "application/json; charset=utf-8" -rbody rbody -userid $static::adm_user -passwd $static::adm_pwd]
            set json_result [call /Common/sys-exec::json2dict $rbody]

            HTTP::respond 200 content "{\"client_id\": \"$client_id\",\"client_secret\": \"$client_secret\"}" noserver Content-Type "application/json" Connection Close
            event disable all
          } else {
            HTTP::respond 403 content "{\"error\": \"Synchronization failed\",\"error-message\": \"[lindex $json_result 3]\"}" noserver Content-Type "application/json" Connection Close
            event disable all
          }
        } else {
          HTTP::respond 403 content "{\"error\": \"ClientApp binding failed\",\"error-message\": \"[lindex $json_result 3]\"}" noserver Content-Type "application/json" Connection Close
          event disable all
        }
      } else {
        HTTP::respond 403 content "{\"error\": \"ClientApp creation failed\",\"error-message\": \"[lindex $json_result 3]\"}" noserver Content-Type "application/json" Connection Close
        event disable all
      }
    }
  }
}

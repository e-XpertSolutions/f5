when RULE_INIT {
    ###
    # rate limit options
    ###

    set static::request_limit 1000
    set static::window_size 300

    ###
    # define URI endpoints
    ###

    set static::status_uri "/rate_limit_status"
}

when HTTP_REQUEST {

    ###
    # initialize vars
    ###

    set access_token ""
    set client_ip ""

    ###
    # retrieve the access_token. It will be used as a mandatory key to evaluate rate limiting
    ###

    if { [HTTP::header exists Authorization] and [HTTP::header Authorization] contains "Bearer" } {
        set access_token [getfield [HTTP::header Authorization] " " 2]
        set client_ip [IP::client_addr]
    }

    if { !($access_token eq "") } {

        ###
        # provide client with rate limit status
        ###
        set key [sha1 $access_token]
        set count [table lookup $key]
        set time [table timeout -remaining $key]

        ###
        # Provide a status page to the client
        ###

        if { [HTTP::path] eq $static::status_uri and [HTTP::method] eq "GET" } {
            if { $count > 0 } {
                set x_rate_limit_limit "$static::request_limit"
                set x_rate_limit_remaining "[expr {$static::request_limit-$count}]"
                set x_rate_limit_reset "$time"
            } else {
                set x_rate_limit_limit "$static::request_limit"
                set x_rate_limit_remaining "$static::request_limit"
                set x_rate_limit_reset "$static::window_size"
            }
            HTTP::respond 200 content "{\"x-rate-limit-limit\": $x_rate_limit_limit,\"x-rate-limit-remaining\": $x_rate_limit_remaining,\"x-rate-limit-reset\": $x_rate_limit_reset}" noserver Content-Type "application/json" Connection Close
            event disable all
        }  else {

            ###
            # Handle the case where a client reach the rate limit
            ###

            if { $count >= $static::request_limit } {
                set x_rate_limit_limit "$static::request_limit"
                set x_rate_limit_remaining "0"
                set x_rate_limit_reset "$time"

                HTTP::respond 429 content "{\"x-rate-limit-limit\": $x_rate_limit_limit,\"x-rate-limit-remaining\": $x_rate_limit_remaining,\"x-rate-limit-reset\": $x_rate_limit_reset}" noserver Content-Type "application/json" Connection Close
                event disable all
            } else {
                if { $count == 0 } {
                    table add $key 1 $static::window_size $static::window_size
                } else {
                    table incr $key
                }
            }
        }
    }
}

/*
 * Enphase Envoy-S (metered) get production data with token
 *
 * Hubitat connecting to the Enphase Envoy-S (metered) with new firmware that requires a token to access local data
 *
 * Production output from Envoy : [wattHoursToday:xx, wattHoursSevenDays:xx, wattHoursLifetime:xx, wattsNow:xx]
 * Consumption data from Envoy : [wattHoursToday:xx, wattHoursSevenDays:xx, wattHoursLifetime:xx, wattsNow:xx]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at:
 *
 *			http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *	on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *	for the specific language governing permissions and limitations under the License.
 *
 */

void setVersion(){
    state.version = "0.0.6"
    state.appName = "EnvoyLocalData"
}

metadata {
    definition(name: "Enphase Envoy-S Production Data", namespace: "community", author: "(modified from Supun Vidana Pathiranage's code)") {
        capability "Sensor"
        capability "Power Meter"
        capability "Refresh"
        capability "Polling"

        attribute "production_power_now", "number"
        attribute "production_power_average", "number"
        attribute "consumption_power_now", "number"
        attribute "consumption_power_average", "number"
        attribute "excess_power_average", "number"
    }
}

preferences {
    section("URI Data") {
        input "ip", "text", title: "Envoy local IP", required: true
        input "email", "text", title: "Enlighten Email", required: true
        input "pass", "password", title: "Enlighten password", required: true
        input "serial", "text", title: "Envoy Serial Number", required: true
        input "productionmeter", "text", title: "Production Meter eid", required: true
        input "netconsumptionmeter", "text", title: "Net Consumption Meter eid", required: true
        input "polling", "text", title: "Polling Interval (mins)", required: true, defaultValue: "15", range: 1..59
        input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: true
    }
}

void logsOff() {
    log.warn "debug logging disabled..."
    device.updateSetting("logEnable", [value: "false", type: "bool"])
}

void poll() {
    pullData()
}

void refresh() {
    pullData()
}

def setProdStates(production) {
    if (!state.p1) {
        state.p1=production
        return production
    } else if (!state.p2) {
        state.p2=state.p1
        state.p1=production
        return (state.p2+production)/2 as Integer
    } else if (!state.p3) {
        state.p3=state.p2
        state.p2=state.p1
        state.p1=production
        return (state.p3+state.p2+production)/3 as Integer
    } else if (!state.p4) {
        state.p4=state.p3
        state.p3=state.p2
        state.p2=state.p1
        state.p1=production
        return (state.p4+state.p3+state.p2+production)/4 as Integer
    } else {
        Integer avg = (state.p4+state.p3+state.p2+state.p1+production)/5 as Integer
        state.p4=state.p3
        state.p3=state.p2
        state.p2=state.p1
        state.p1=production
        return avg
    }
}

def setConsStates(consumption) {
    if (!state.c1) {
        state.c1=consumption
        return consumption
    } else if (!state.c2) {
        state.c2=state.c1
        state.c1=consumption
        return (state.c2+consumption)/2 as Integer
    } else if (!state.c3) {
        state.c3=state.c2
        state.c2=state.c1
        state.c1=consumption
        return (state.c3+state.c2+consumption)/3 as Integer
    } else if (!state.c4) {
        state.c4=state.c3
        state.c3=state.c2
        state.c2=state.c1
        state.c1=consumption
        return (state.c4+state.c3+state.c2+consumption)/4 as Integer
    } else {
        Integer avg = (state.c4+state.c3+state.c2+state.c1+consumption)/5 as Integer
        state.c4=state.c3
        state.c3=state.c2
        state.c2=state.c1
        state.c1=consumption
        return avg
    }
}

void pullData() {
    String ip = settings.ip - "https://" - "http://" - "/"
    String production_url = "https://" + ip + "/ivp/meters/readings"
    List energy_data = []

    if (logEnable) log.debug "Pulling data..."
    String token = getToken()
    if (token != null) {
        Map<String> headers = [
                "Authorization": "Bearer " + token
        ]
        Map<String, Object> httpParams = [
                "uri"               : production_url,
                "contentType"       : "application/json",
                "requestContentType": "application/json",
                "ignoreSSLIssues"   : true,
                "headers"           : headers
        ]

        try {
            httpGet(httpParams) { resp ->
                if (logEnable) {
                    if (resp.data) log.debug "${resp.data}"
                }
                if (resp.success) {
                    energy_data = resp.data
                }
            }
        } catch (Exception e) {
            log.warn "HTTP get failed: ${e.message}"
        }

        Map production_data = energy_data.find{ it.eid == settings.productionmeter as Integer }
        Map consumption_data = energy_data.find{ it.eid == settings.netconsumptionmeter as Integer }
        Integer net_metering = -consumption_data?.activePower as Integer
        Integer production = production_data?.activePower as Integer
        Integer consumption = production - net_metering

        sendEvent(name: "production_power_now", value: production, isStateChange: true)
        sendEvent(name: "consumption_power_now", value: consumption, isStateChange: true)
        sendEvent(name: "power", value: net_metering, unit: "w", isStateChange: true)
        
        Integer avg_prod = setProdStates(production)
        sendEvent(name: "production_power_average", value: avg_prod, isStateChange: true)
        
        Integer avg_cons = setConsStates(consumption)
        sendEvent(name: "consumption_power_average", value: avg_cons, isStateChange: true)
        
        sendEvent(name: "excess_power_average", value: avg_prod-avg_cons, isStateChange: true)

		
    } else
        log.warn "Unable to get a valid token. Aborting..."
}

boolean isValidToken(String token) {
    boolean valid_token = false
    String response
    String ip = settings.ip - "https://" - "http://" - "/"
    String token_check_url = "https://" + ip + "/auth/check_jwt"

    if (logEnable) log.debug "Validating the token"
    Map<String> headers = [
            "Authorization": "Bearer " + token
    ]
    Map<String, Object> httpParams = [
            "uri"               : token_check_url,
            "contentType"       : "text/html",
            "requestContentType": "application/json",
            "ignoreSSLIssues"   : true,
            "headers"           : headers
    ]
    try {
        httpGet(httpParams) { resp ->
            if (logEnable) {
                if (resp.data) log.debug "${resp.data}"
            }
            if (resp.success) {
                response = resp.data
                if (response.contains("Valid token.")) {
                    valid_token = true
                }
            }
        }
    } catch (Exception e) {
        log.warn "HTTP get failed: ${e.message}"
    }
    return valid_token
}

String getSession() {
    String session
    String login_url = "https://enlighten.enphaseenergy.com/login/login.json"

    if (logEnable) log.debug "Generating a session"
    Map<String> data = [
            "user[email]"   : settings.email,
            "user[password]": settings.pass
    ]
    Map<String, Object> httpParams = [
            "uri" : login_url,
            "body": data
    ]
    try {
        httpPost(httpParams) { resp ->
            if (logEnable) {
                if (resp.data) log.debug "${resp.data}"
            }
            if (resp.success) {
                session = resp.data?.session_id
            }
        }
    } catch (Exception e) {
        log.warn "HTTP post failed: ${e.message}"
    }

    if (logEnable) log.debug "Session Id: ${session}"
    return session
}

String getToken() {
    String valid_token
    String current_token
    // migrate from attribute to state variable
    if (state.jwt_token != null) {
        current_token = state.jwt_token
    } else if (device.currentValue("jwt_token", true) != null) {
        state.jwt_token = device.currentValue("jwt_token", true)
    }
    if (logEnable) log.debug "Retrieving the token"
    if (current_token != null && isValidToken(current_token)) {
        if (logEnable) log.debug "Current token is still valid. Using it. "
        valid_token = current_token
    } else {
        if (logEnable) log.debug "Current token is expired. Generating a new one."
        String session = getSession()
        if (session != null) {
            String token_generated = generateToken(session)
            if (token_generated != null && isValidToken(token_generated)) {
                state.jwt_token = token_generated
                valid_token = token_generated
            } else {
                log.warn "Generated token is not valid. Investigate with debug logs"
            }
        } else {
            log.warn "Generated session is null. Investigate with debug logs"
        }
    }
    return valid_token
}

String generateToken(String session_id) {
    String token
    String tokenUrl = "https://entrez.enphaseenergy.com/tokens"

    if (logEnable) log.debug "Generating a new token"
    Map<String> data = [
            "session_id": session_id,
            "serial_num": settings.serial,
            "username"  : settings.email
    ]
    Map<String, Object> httpParams = [
            "uri"               : tokenUrl,
            "contentType"       : "text/html",
            "headers"           : ["Accept" : "application/json"],
            "requestContentType": "application/json",
            "body"              : data
    ]
    if (logEnable) log.debug "HTTP params: ${httpParams}"
    try {
        httpPost(httpParams) { resp ->
            if (logEnable) {
                if (resp.data) log.debug "HTTP response: ${resp.data}"
            }
            if (resp.success) {
                token = resp.data
            }
        }
    } catch (Exception e) {
        log.warn "HTTP post failed: ${e.message}"
    }
    if (logEnable) log.debug "Generated token : ${token}"
    return token
}

void setPolling() {
    unschedule()
    def sec = Math.round(Math.floor(Math.random() * 60))
    def min = Math.round(Math.floor(Math.random() * settings.polling.toInteger()))
    String cron = "${sec} ${min}/${settings.polling.toInteger()} * * * ?" // every N min
    schedule(cron, pullData)
}

#define ENABLE_TRACE

#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <osip.h>

const char *WiFiSSID    = "YourSSID";          // WiFi SSID
const char *WiFiPSK     = "YourPassword";  // WiFi WPA2 preshared key

const char *WiFiIP      = "192.168.1.89";       // WiFi IP of the ESP
const char *WiFiGW      = "192.168.1.1";        // WiFi GW
const char *WiFiNM      = "255.255.255.0";      // WiFi NM
const char *WiFiDNS     = "192.168.1.1";        // WiFi DNS

const unsigned int localPort = 5060;      // local port to listen on

// buffers for receiving and sending data
char rxBuffer[UDP_TX_PACKET_MAX_SIZE + 1]; // buffer to hold incoming packet
char txBuffer[UDP_TX_PACKET_MAX_SIZE + 1]; // buffer to hold outgoing packet

WiFiUDP udp;

osip_t *osip;
//osip_message_t *message;

void setup() {
  IPAddress myIP;
  IPAddress myGW;
  IPAddress myNM;
  IPAddress myDNS;

  WiFi.setAutoConnect (true);
  WiFi.setAutoReconnect (true);
  
  myIP.fromString(WiFiIP);
  myGW.fromString(WiFiGW);
  myNM.fromString(WiFiNM);
  myDNS.fromString(WiFiDNS);

  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.config(myIP, myGW, myNM, myDNS);

  digitalWrite(LED_BUILTIN, LOW);
  if (String(WiFiSSID) != WiFi.SSID()) {
    Serial.print("Wifi initializing...\r\n");
    WiFi.begin(WiFiSSID, WiFiPSK);
  }
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print('.');
    delay(250);
  }
  digitalWrite(LED_BUILTIN, HIGH);

  WiFi.persistent(true);
  
  Serial.print("Connected! IP address: ");
  Serial.println(WiFi.localIP());
  Serial.printf("UDP server on port %d\n", localPort);
  Serial.printf("Max packet size: %d\n", UDP_TX_PACKET_MAX_SIZE);
  udp.begin(localPort);

  Serial.println("Initializing oSIP...");
  if (osip_init(&osip) != 0) {
    Serial.println("Failed to initialize oSIP! Halting.");
    udp.stop();
    Serial.end();
    delay(1000);
    ESP.deepSleep(0);
  }

  osip_trace_initialize_func(END_TRACE_LEVEL, &printf_trace_func);
  osip_set_cb_send_message(osip, &cb_send_udp_sip_msg);
  osip_set_message_callback(osip, OSIP_IST_INVITE_RECEIVED, &cb_ist_invite_received);
  osip_set_message_callback(osip, OSIP_IST_ACK_RECEIVED, &cb_ist_ack_received);
  osip_set_kill_transaction_callback(osip, OSIP_IST_KILL_TRANSACTION, &cb_ist_kill_transaction);
  Serial.println("Ready!");
}

void loop() {
  // TODO: Somewhere on each INVITE -> BUSY transaction I'm losing 72 bytes of heap.
  // 31968 31896 31824 31752 31680
  // After about for or five transactions it starts failing
  // Sending an additional TRYING response makes it worse: 144 bytes per transaction
  // 31880 31736 31592
  // Seems clear that there's something wrong with the message sending
  // Could be in building the message, processing the message through the FSM, and/or the UDP stuff
  process_udp();
  process_osip();
//    Serial.println("Parsing SIP message...");
//    osip_message_init(&message);
//    if (osip_message_parse(message, rxBuffer, n) != 0) {
//      Serial.println("Failed to parse SIP message");
//    } else {
//      Serial.println("Parsed SIP message");
//      char *buf;
//      size_t len;
//      Serial.println("Printing SIP message...");
//      osip_message_to_str(message, &buf, &len);
//      Serial.println(buf);
//      osip_free(buf);
//    }
//    osip_message_free(message);

    // send a reply, to the IP address and port that sent us the packet we received
//    udp.beginPacket(udp.remoteIP(), udp.remotePort());
//    udp.write(txBuffer);
//    udp.endPacket();

//    digitalWrite(LED_BUILTIN, HIGH);
//  }

}

void process_udp() {
  // if there's data available, read a packet
  // TODO: packet reassembly. Looks like these babies get split up at 1024 bytes
  int packetSize = udp.parsePacket();
  if (packetSize) {
    digitalWrite(LED_BUILTIN, LOW);
    Serial.printf("Received packet of size %d from %s:%d\n    (to %s:%d, free heap = %d B)\n",
                  packetSize,
                  udp.remoteIP().toString().c_str(), udp.remotePort(),
                  udp.destinationIP().toString().c_str(), udp.localPort(),
                  ESP.getFreeHeap());

    // read the packet into rxBufffer
    int n = udp.read(rxBuffer, UDP_TX_PACKET_MAX_SIZE);
    rxBuffer[n] = 0;
    Serial.println("Contents:");
    Serial.println(rxBuffer);

    Serial.println("Parsing SIP message.");
    osip_event_t *evt = osip_parse(rxBuffer, n);
    if (evt == NULL) {
      Serial.println("Failed to parse SIP message.");
    } else {
      Serial.println("Looking for existing transaction.");
      if (osip_find_transaction_and_add_event(osip, evt) != OSIP_SUCCESS) {
        Serial.println("No transaction found. Creating a new one.");
        osip_transaction_t *txn = osip_create_transaction(osip, evt);
        osip_transaction_add_event(txn, evt);
      }
      Serial.println("oSIP event added.");
    }

    Serial.printf("Number of IST transactions: %d\n", osip_list_size(&osip->osip_ist_transactions));
    digitalWrite(LED_BUILTIN, HIGH);
  }
}

void process_osip() {
//  osip_ict_execute(osip);
  osip_ist_execute(osip);
//  osip_nict_execute(osip);
//  osip_nist_execute(osip);
//  osip_timers_ict_execute(osip);
  osip_timers_ist_execute(osip);
//  osip_timers_nict_execute(osip);
//  osip_timers_nist_execute(osip);
}

int cb_send_udp_sip_msg(osip_transaction_t* txn, osip_message_t* msg, char* host, int port, int sock) {
  Serial.println("Sending UDP message");
  char *buf;
  size_t len;
  Serial.println("Printing SIP message...");
  int result = osip_message_to_str(msg, &buf, &len);
  if (result != OSIP_SUCCESS) {
    Serial.printf("Failed to serialize message: %d\n", result);
    if (buf != NULL) {
      osip_free(buf);
    }
    return result;
  }
  Serial.println(buf);
  if (!udp.beginPacket(host, port)) {
    osip_free(buf);
    return OSIP_NO_NETWORK;
  }
  udp.write(buf, len);
  
  if (!udp.endPacket()) {
    result = OSIP_NO_NETWORK;
  }
  
  osip_free(buf);

  return result;
}

int build_response(osip_message_t *request, osip_message_t **response) {
  osip_message_t *msg;
  osip_message_init(&msg);

  osip_call_id_clone(request->call_id, &msg->call_id);
  osip_to_clone(request->to, &msg->to);
  osip_cseq_clone(request->cseq, &msg->cseq);
  osip_call_id_clone(request->call_id, &msg->call_id);

  int pos = 0;
  while (!osip_list_eol (&request->vias, pos)) {
    osip_via_t *srcVia;
    osip_via_t *dstVia;

    srcVia = (osip_via_t *)osip_list_get(&request->vias, pos);
    int result = osip_via_clone(srcVia, &dstVia);
    if (result != OSIP_SUCCESS) {
      osip_message_free(msg);
      return result;
    }
    osip_list_add(&(msg->vias), dstVia, -1);
    pos++;
  }

  osip_to_set_tag(msg->to, osip_strdup("8637729"));
  osip_message_set_version(msg, osip_strdup("SIP/2.0"));
  osip_message_set_user_agent(msg, osip_strdup("EspPager/0.1.0 (osip2/5.2.1)"));

  *response = msg;
  return 0;
}

void cb_ist_invite_received(int type, osip_transaction_t *txn, osip_message_t *msg) {
  // TODO: Beep the buzzer
  Serial.println("Invite received");
  
  osip_message_t *response;
  osip_event_t *evt;

//  build_response(msg, &response);
//  osip_message_set_status_code(response, SIP_TRYING);
//  osip_message_set_reason_phrase(response, osip_strdup("Trying"));
//  evt = osip_new_outgoing_sipmessage(response);
//  osip_transaction_add_event(txn, evt);

  build_response(msg, &response);
  osip_message_set_status_code(response, SIP_TEMPORARILY_UNAVAILABLE);
  osip_message_set_reason_phrase(response, osip_strdup("Temporarily unavailable"));
  evt = osip_new_outgoing_sipmessage(response);
  osip_transaction_add_event(txn, evt);

  Serial.println("Invite response sent (480 Temporarily unavailable)");
}

void cb_ist_ack_received(int type, osip_transaction_t *txn, osip_message_t *msg) {
  Serial.println("Ack received");
  
  //osip_transaction_free(txn);
}

void cb_ist_kill_transaction(int type, osip_transaction_t *txn) {
  // TODO: Print the Call-ID?
  Serial.println("Transaction killed.");
  osip_transaction_free(txn);
}


void printf_trace_func(const char *fi, int li, osip_trace_level_t level, const char *chfr, va_list ap) {
    const char* desc = "       ";
    switch(level) {
    case OSIP_FATAL:
        desc = " FATAL ";
        break;
    case OSIP_BUG:
        desc = "  BUG  ";
        break;
    case OSIP_ERROR:
        desc = " ERROR ";
        break;
    case OSIP_WARNING:
        desc = "WARNING";
        break;
    case OSIP_INFO1:
        desc = " INFO1 ";
        break;
    case OSIP_INFO2:
        desc = " INFO2 ";
        break;
    case OSIP_INFO3:
        desc = " INFO3 ";
        break;
    case OSIP_INFO4:
        desc = " INFO4 ";
        break;
    default:
        desc = "       ";
    }
    
//    Serial.printf("|%s| <%s: %i> | ", desc, fi, li);
//    vprintf(chfr, ap);
//    printf ("\n");
    Serial.printf("|%s| <%s: %i> | %s\n", desc, fi, li, chfr);
}

/*
  test (shell/netcat):
  --------------------
    nc -u 192.168.esp.address 8888
*/

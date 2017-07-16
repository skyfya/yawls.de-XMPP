---------- Serverweite Einstellungen ----------
-- Alle Einstellungen die hier gemacht werden betreffen den ganzen Server
-- und sind für alle Virtuellen Hosts gültig

admins = { "admin@domain.tld", "admin2@domain.tld" }

-- Enable use of libevent for better performance under high load
-- For more information see: http://prosody.im/doc/libevent
--use_libevent = true;

-- Globale config --


-- This is the list of modules Prosody will load on startup.
-- It looks for mod_modulename.lua in the plugins folder, so make sure that exists too.
-- Documentation on modules can be found at: http://prosody.im/doc/modules

plugin_paths = { "/dein/pfad/zu/den/prosody-modulen" }

modules_enabled = {

	-- Generally required
		"roster"; 	-- Allow users to have a roster. Recommended ;)
		"saslauth"; 	-- Authentication for clients and servers. Recommended if you want to log in.
		"tls"; 		-- Add support for secure TLS on c2s/s2s connections
		"dialback"; 	-- s2s dialback support
		"disco"; 	-- Service discovery

	-- Not essential, but recommended
		"private"; 	-- Private XML storage (for room bookmarks, etc.)
		"vcard"; 	-- Allow users to set vCards
	
	-- These are commented by default as they have a performance impact
		"privacy";		--erlaubt dem Benutzer, einen Status für bestimmte Benutzer vorzugeben
		--"compression"; -- Stream compression (Debian: requires lua-zlib module to work)

	-- Nice to have
		"version"; 	-- Replies to server version requests
		"uptime"; 	-- Report how long server has been running
		"time"; 	-- Let others know the time here on this server
		"ping"; 	-- Replies to XMPP pings with pongs
		"pep"; 		-- Enables users to publish their mood, activity, playing music and more
		"register"; 	-- Erlaubt es sich am Server via Client zu regestrieren bzw. das Passwort zu ändern
		"register_web";	-- Schaltet das WebInterface zum Registrieren frei
		"announce";	-- ermöglicht dem Administrator, eine Nachricht an alle Online-Benutzer zu senden
		"blocking";	-- Modul, mit dem Benutzer Blockierlisten verwalten können
		"carbons";	-- Synchronisieren des Chatverlaufs zwischen unterschiedlichend Clients
		"webpresence";	-- Zeigt den OnlineStatus an /status/jid/text,message,html

	-- Admin interfaces
		"admin_adhoc"; 	-- Allows administration via an XMPP client that supports ad-hoc commands
		"admin_web"; 	-- WebInterface über Port 5281
		--"admin_telnet"; -- Opens telnet console interface on localhost port 5582
				
	-- HTTP modules
		"bosh";		-- Enable BOSH clients, aka "Jabber over HTTP"
		"http_files";	-- Server static files from a directory over HTTP
		"http";		-- der HTTP(S)-Server von Prosody, von dem z.B. http_upload abhängt
		"http_upload";	-- ermöglicht den Upload von Dateien


	-- Other specific functionality
		"lastlog";		-- Aktiv damit "list_inactive" auch filtern kann
		"posix";		-- POSIX functionality, sends server to background, enables syslog, etc.
		"watchregistrations";	--Sendet Nachrichten bei der Registrierung neuer Benutzer an konfigurierte Adressen
		"welcome";		--erlaubt dem Administrator, eine Willkommensnachricht einzustellen
		"log_auth";		--protokolliert die Anmeldeversuche
		"mam";			--Speichert die ChatProtokolle der User
		--"motd";		-- Send a message to users when they log in
		"legacyauth";		-- Legacy authentication. Only used by some old clients and bots.
		--"groups";		-- Shared roster support


	-- Testing Area (Mods die erst getestet und dann dauerhaft hinzugefügt werden
		"stanza_counter";	-- Soll eingehende und ausgehnde Verbindungen zählen siehe /counter/
		"server_status";	-- zeigt die Anzahl der Verbindungen + den Status der Dienste an siehe /server-info/
		"serverinfo";		-- mode_Serverinfo von ThomasLeister (TrashServer.net)
		--"mam_muc";		-- Ermöglicht es beim "rejoin" die letzten x nachrichten vom Server zu bekommen, deaktviert da erst mit 0.10 stabil
		"register_redirect";	-- Sollte die Registrierung über einen Client erfolgen bekommt man den Hinweis auf die Register-Seite zu gehen
		"smacks";		-- XEP-0198 Stream Management bei kurzzeitigen verbinungsabbrüchen
		"csi";			-- CLIENT STATUS INDICATOR tut nichts ohne mod_throttle_presence & mode_filter_chatstats
		"throttle_presence";	-- reduziert den Traffic an mobile Geräten für Statusänderungen (spart batterie) (benötigt CSI)
		"filter_chatstates";	-- reduziert den Batterie verbauch an Mobilen-Geräten wenn CSI aktiv ist
		"cloud_notify";		-- XEP-0357
		"proxy65";		-- XEP-0065 ermöglicht die Übertragung zwischen Endgeräten die hinter NAT Routern hängen
};


-- Erstellen von Accounts via Clients sollte ausgeschalttet werden um Spam zuvermeiden
-- in diesem Fall ist es an da das Modul "register_redirect" für uns den Clients mitteilt
-- wie Sie sich am Server regestrieren können 
-- For more information see http://prosody.im/doc/creating_accounts

allow_registration = true;

-- Debian:
--   send the server to background.
--

daemonize = true;

-- Debian:
--   Please, don't change this option since /var/run/prosody/
--   is one of the few directories Prosody is allowed to write to
--
pidfile = "/var/run/prosody/prosody.pid";

-- Pfad zu eueren Zertifikaten ich empfehle LetsEncrypt
ssl = {
	key = "/etc/prosody/certs/privkey.pem";
	certificate = "/etc/prosody/certs/fullchain.pem";
}

-- Verschlüsselte Verbindungen zu Clients und Servern erzwingen
c2s_require_encryption = true
s2s_require_encryption = true

-- Server müssen anerkannte, gültigen Sicherheitszertifikate vorweisen andernfalls werden Sie abgehlehnt.
-- Macht das Netz etwas sichherer
s2s_secure_auth = true

-- Passwörter gehashed abspeichern
authentication = "internal_hashed"

-- Anbindung an SQL DB evtl. mal testen!

--storage = "sql" -- Standard ist "internal" 
--sql = { driver = "MySQL", database = "prosody", username = "prosody", password = "secret", host = "localhost" }


-- Einstellung für die Logs
-- Debian:
--  Logs info and higher to /var/log
--  Logs errors to syslog also
log = {
	-- Log files (change 'info' to 'debug' for debug logs):
	info = "/var/log/prosody/prosody.log";
	error = "/var/log/prosody/prosody.err";
	-- Syslog:
	{ levels = { "error" }; to = "syslog";  };
}

-- Stanza Counter HTTP
---------------------------------
stanza_counter_basepath = "/counter/"

-- Server_Status MOD
---------------------------------
server_status_basepath = "/server-info/"
server_status_show_hosts = { "domain.tld" }
server_status_show_comps = { "conversation.domain.tld" }
server_status_json = true

-- Template für mod_register_web
----------------------------------
register_web_template = "/etc/prosody/template/Prosody-Web-Registration-Theme";

-- register_redirct Einstellungen
----------------------------------

registration_whitelist = { "*your whitelisted web server ip address*" }
registrarion_url = "https://domain.tld/register"
registration_text = "Bitte benutze das Formular auf der Seite *https://domain.tld/register* , um dir einen Account anzulegen"
-- registration_oob = true (default) or false, in the case there's no applicable OOB method (e.g. the server admins needs to be contacted by phone)

-- HTTP Config
----------------------------------

http_default_host = "domain.tld"

http_paths = {
    register_web = "/register";
}

-- BOSH-Funktionalität auch für Clients auf anderen Domains freigeben
-- BOSH steht unter https://domain.tld:5281/http-bind/ zur Verfügung

cross_domain_bosh = true;

-- Proxy Interface Config
-----------------------------------
proxy65_ports = { 5000 }
proxy65_interfaces = {"*", "::"}


--
-- Service Discovery
----------------------------------

-- Multi-User-Chat (MUC) soll als verfügbarer XMPP Dienst aufgeführt werden
disco_items = {
    { "conversation.domain.tld", "Chatrooms" };
}

----------- Virtual hosts -----------

VirtualHost "domain.tld"
        enabled = true
        ssl = {
                key = "/etc/prosody/certs/privkey.pem";
                certificate = "/etc/prosody/certs/fullchain.pem";

                options = { "no_sslv2", "no_ticket", "no_compression", "no_sslv3" };
                -- Disable some not paranoid-capable ciphers.
                ciphers = "HIGH:!DSS:!aNULL@STRENGTH!:!DES-CBC3-SHA:!ECDHE-RSA-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA";
                -- Allow perfect forward secrecy.
                dhparam = "/etc/prosody/certs/domain.tld.dh-2048.pem";
                }

	-- Regestrieren erlauben / verbieten
	---------------------------------

	allow_registration = true
	in_seconds_between_registrations = 86400

	http_host = "domain.tld"

	-- MAM Einstellungen 
	-- Chats werden nicht standartmäßig geloggt "policy = false;" ,
	-- und Archive nach einem Monat vom Server gelöscht
	--------------------------------------------------------------
	default_archive_policy = true;
	archive_expires_after = "1m";

	-- Watchregistrations Einstellungen
	--------------------------------------------------------------
	registration_watchers = { "watcher@domain.tld"  }
	registration_notification = "User $username just registered on $host from $ip"
	welcome_message = "Hallo $username, Willkommen auf $host IM server!"


	-- Compenten Einstellungen folgen hier
	--------------------------------------------------------------

	-- Upload
	--------------------
	Component "upload.domain.tld" "http_upload"
		http_upload_file_size_limit = 52428800 -- Upload zur Zeit nicht mehr wie 50MB
		http_upload_expire_after = 60 * 60 * 24 * 30 -- Löschung nach 30Tagen in Sekunden

	-- MUC 
	--------------------
	Component "conversation.domain.tld" "muc"
		name = "Chatrooms"
		restrict_room_creation = false
		max_history_messages = 500

	-- Proxy65
	--------------------
	Component "proxy.domain.tld" "proxy65"
		proxy65_address = "proxy.domain.tld"
		proxy65_acl = { "domain.tld" , "user@domain.tld"}

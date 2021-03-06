require 'omniauth'
require "omniauth/heart/version"

module OmniAuth
  module Strategies

    class Heart

      include OmniAuth::Strategy

      # Default options
      option :claim_expiration, 60  # Number of seconds token claims should last

      option :client_options, {
        auth_server_uri: nil,       # Base URI for the authorization server
        callback_suffix: nil,       # Additional params for callback from auth server
        client_id: nil,             # Client ID registered with authorization server
        jwt_signing_key: nil        # Key used to sign JSON Web Tokens 
      }

      credentials do
        { 
          access_token: @access_token
        }
      end

      #---------------------------------------------------------------------------

      ##
      # The request to the resource server was unauthorized, so we redirect the
      # request to authorization server to get an authorization code.  
      #
      # If successful, the callback URL we provide will be called by the 
      # authorization server with the authorization code.
      
      def request_phase
        log :debug, "====== Entering Heart::request_phase ======"
        redirect(authorize_path)
      end

      #---------------------------------------------------------------------------

      ##
      # Called when the authorization server grants us an authorization code.  With
      # the authorization code, we make another call to the authorization server to
      # request an access token.  We need the access token to access resources from
      # the resource server.

      def callback_phase
        log :debug, "====== Entering Heart::callback_phase ======"

        @access_token = request_access_token(request)
        log :debug, "------ Access token = #{@access_token} ------"

        super
      end

      #-------------------------------------------------------------------------------
      private
      #-------------------------------------------------------------------------------

      ##
      # Creates the URI to access the authorization server's authorization endpoint
      # with the appropriate parameters (e.g. client ID).  The client ID was provided 
      # when we registered the client with the authorization server.
      #
      # A random state is also passed along as part of the URI to help us ensure that 
      # further communication for this authorization is not due to a CSRF attack.
      #
      # Returns:
      #   +String+::                Path and parameters to get authorization code

      def authorize_path
        session[:state] = "#{Time.now.to_i}/#{SecureRandom.hex(18)}"

        auth_server_config["authorization_endpoint"] + "?" +
                                "response_type=code&" +
                                "client_id=#{client_options.client_id}&" + 
                                "redirect_uri=#{generate_callback_path}&" +
                                "state=#{session[:state]}"
      end

      #-------------------------------------------------------------------------------

      ##
      # Requests a new access token from the authorization server.
      # 
      # We have received the redirect callback from the authorization server with an 
      # authorization code.  Now we issue another request to the authorization server 
      # with that code to get an access token, this time with a JSON Web Token signed 
      # with our private key.  We need the access token to retrieve information from 
      # the protected resource server.
      #
      # Params:
      #   +request_from_server+::   Request from auth server on authorization completion
      #
      # Returns:
      #   +String+::                Access token if successful, otherwise nil

      def request_access_token(request_from_server)
        log :debug, "========= Entering AuthorizationServer::request_access_token ========="

        if valid_state?(request_from_server.params["state"])
          log :debug, "--------- State is valid ---------"

          response = auth_server.post(auth_server_config["token_endpoint"]) do |request|
            request.body = {
              "grant_type"                => "authorization_code",
              "code"                      => request_from_server.params["code"],
              "redirect_uri"              => generate_callback_path,
              "client_id"                 => client_options.client_id,
              "client_assertion_type"     => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              "client_assertion"          => jwt_token(token_endpoint_claims)
            }

            log :debug, "--------- request.headers = #{request.headers.inspect} ----------"
            log :debug, "--------- request.body = #{request.body.inspect} ---------"
          end

          log :debug, "--------- response.headers = #{response.headers.inspect} ----------"
          log :debug, "--------- response.body = #{response.body} ----------"
          log :debug, "--------- response.status = #{response.status} ----------"

          if OK == response.status
            parsed_response = JSON.parse(response.body)
            parsed_response["access_token"]
          else
            raise "Call to get access token from authorization server failed. #{response.inspect}"
          end
        else
          # Log, but ignore potential CSRF attacks
          log :warn, "///////// State is invalid - possible CSRF attack /////////"
        end
      end

      #-------------------------------------------------------------------------------

      ##
      # Get authorization server endpoints and configuration settings.  The 
      # configuration is cached in an instance variable so we don't have to keep
      # asking the server.
      #
      # Returns:
      #   +Hash+::              Hash of endpoints and settings for authorization server

      def auth_server_config
        @auth_server_config ||= discover_config
      end

      #-------------------------------------------------------------------------------

      ##
      # Establish a connection object that will be reused during communication 
      # with the authorization server.  The connection is cached in an instance
      # variable.

      def auth_server
        @auth_server ||= Faraday.new(client_options.auth_server_uri, 
                                          :ssl => {:verify => false}) do |builder|
          builder.request   :url_encoded    # Encode request parameters as "www-form-urlencoded"
          builder.response  :logger         # Log request and response to STDOUT
          builder.adapter   :net_http       # Perform requests with Net::HTTP
        end
      end

      #-------------------------------------------------------------------------------

      ##
      # Calls the authorization server to retrieve its endpoints and configuration
      # settings.
      #
      # Returns:
      #   +Hash+::              Hash of endpoints and settings for authorization server

      def discover_config
        log :debug, "------ Calling #{config_endpoint} ------"

        response = auth_server.get("#{config_endpoint}")

        if OK == response.status
          JSON.parse(response.body)
        else
          raise "Could not get configuration from authorization server. #{response.inspect}"
        end
      end

      #-------------------------------------------------------------------------------

      ##
      # This method creates a JSON Web Token (JWT) so that we can authenticate with
      # the authorization server.
      #
      # Returns:
      #   +String+::            Signed JSON Web Token

      def jwt_token(claims)
        log :debug, "    ------ claims = #{claims.inspect} ------"
        log :debug, "    ------ jwt_signing_key = #{client_options.jwt_signing_key} ------"
        # Sign our claims with our private key.  The authorization server will 
        # contact our jwks_uri endpoint to get our public key to decode the JWT.

        JWT.encode(claims, client_options.jwt_signing_key, 'RS256')
      end

      #-------------------------------------------------------------------------------

      ##
      # This method defines the claims for the JSON Web Token (JWT) we use to
      # authenticate with the authorization server.
      #
      # Returns:
      #   +Hash+::              Set of claims for JSON Web Token

      def token_endpoint_claims
        now = Time.now.to_i

        {
          iss: client_options.client_id,                # Issuer (FHIR Client)
          sub: client_options.client_id,                # Subject of request (FHIR Client)
          aud: auth_server_config["token_endpoint"],    # Intended audience (Authorization Server)
          iat: now,                                     # Time of issue
          exp: now + options.claim_expiration,          # Expiration time
          jti: "#{now}/#{SecureRandom.hex(18)}",        # Unique ID for request
        }
      end

      #-------------------------------------------------------------------------------

      ##
      # Determines whether the random state value we passed during the authorization 
      # code phase of the OAuth2 process matches the state value sent with subsequent 
      # requests.
      #
      # Params:
      #   +state+::           State value received during callbacks.
      #
      # Returns:
      #   +Boolean+::         true if state values match, otherwise false.

      def valid_state?(state)
        log :debug, "    ------ Expected state #{session[:state]}, received #{state} ------"
        session[:state] == state
      end

      #-------------------------------------------------------------------------------

      def generate_callback_path
        full_host + script_name + callback_path + client_options.callback_suffix
      end

      #-------------------------------------------------------------------------------

      ## 
      # Determines endpoint to retrieve the authorization server configuration.

      def config_endpoint
        "#{client_options.auth_server_uri}/.well-known/openid-configuration"
      end

      #-------------------------------------------------------------------------------

      def client_options
        options.client_options
      end

    end
  end
end


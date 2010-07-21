module Recaptcha
  module Verify
    # determine the certificate authority path to verify SSL certs
    CA_FILES = %w(/etc/ssl/certs/ca-certificates.crt /usr/share/curl/curl-ca-bundle.crt)
    CA_FILES.each do |ca_file|
      if File.exists?(ca_file)
        CA_FILE = ca_file
        break
      end
    end
    CA_FILE = nil unless defined?(CA_FILE)

    # Your private API can be specified in the +options+ hash or preferably
    # the environment variable +RECAPTCHA_PUBLIC_KEY+.
    def verify_recaptcha(options = {})
      if !options.is_a? Hash
        options = {:model => options}
      end
      
      env = options[:env] || ENV['RAILS_ENV']
      return true if SKIP_VERIFY_ENV.include? env
      model = options[:model]
      attribute = options[:attribute] || :base
      private_key = options[:private_key] || ENV['RECAPTCHA_PRIVATE_KEY']
      raise RecaptchaError, "No private key specified." unless private_key
      ssl = options[:ssl]

      begin
        recaptcha = nil
        Timeout::timeout(options[:timeout] || 3) do
          if ssl
            url = URI.parse("https://#{RECAPTCHA_VERIFY_SERVER}/verify")
            https = Net::HTTP.new(url.host, (url.port || 443))
            https.use_ssl = true
            if options[:ca_file] || CA_FILE
              https.ca_file = options[:ca_file] || CA_FILE
              https.verify_mode = OpenSSL::SSL::VERIFY_PEER
              https.verify_depth = 5
            else
              https.verify_mode = OpenSSL::SSL::VERIFY_NONE
            end
            https.start do |http|
              recaptcha = Net::HTTP.post_form url, {
                "privatekey" => private_key,
                "remoteip"   => request.remote_ip,
                "challenge"  => params[:recaptcha_challenge_field],
                "response"   => params[:recaptcha_response_field]
              }
            end
          else
            recaptcha = Net::HTTP.post_form URI.parse("http://#{RECAPTCHA_VERIFY_SERVER}/verify"), {
              "privatekey" => private_key,
              "remoteip"   => request.remote_ip,
              "challenge"  => params[:recaptcha_challenge_field],
              "response"   => params[:recaptcha_response_field]
            }
          end
        end
        answer, error = recaptcha.body.split.map { |s| s.chomp }
        unless answer == 'true'
          flash[:recaptcha_error] = error
          if model
            model.valid?
            model.errors.add attribute, options[:message] || "Word verification response is incorrect, please try again."
          end
          return false
        else
          flash[:recaptcha_error] = nil
          return true
        end
      rescue Timeout::Error 
        flash[:recaptcha_error] = "recaptcha-not-reachable"
        if model
          model.valid?
          model.errors.add attribute, options[:message] || "Oops, we failed to validate your word verification response. Please try again."
        end
        return false
      rescue Exception => e
        raise RecaptchaError, e.message, e.backtrace
      end
    end # verify_recaptcha
  end # Verify
end # Recaptcha

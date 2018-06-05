# frozen_string_literal: true

require "pathname"
require "active_support/message_encryptor"

module ActiveSupport
  class EncryptedFile
    class MissingContentError < RuntimeError
      def initialize(content_path)
        super "Missing encrypted content file in #{content_path}."
      end
    end

    class MissingKeyError < RuntimeError
      def initialize(key_path:, env_key:)
        super \
          "Missing encryption key to decrypt file with. " +
          "Ask your team for your master key and write it to #{key_path} or put it in the ENV['#{env_key}']."
      end
    end

    CIPHER = "aes-128-gcm"

    def self.generate_key
      SecureRandom.hex(ActiveSupport::MessageEncryptor.key_len(CIPHER))
    end


    attr_reader :content_path, :key_path, :env_key, :raise_if_missing_key, :key

    def initialize(content_path:, key_path:, env_key:, raise_if_missing_key:)
      @content_path, @key_path = Pathname.new(content_path), key_path
      @env_key, @raise_if_missing_key = env_key, raise_if_missing_key
    end

    def read
      raise MissingContentError unless content_path.exist?

      try_read || handle_missing_key
    end

    def write(contents)
      try_read || use_first_available_key
      IO.binwrite "#{content_path}.tmp", encrypt(contents)
      FileUtils.mv "#{content_path}.tmp", content_path
    end

    def change(&block)
      writing read, &block
    end


    private

      def try_read
        return unless content_path.exist?
        content = content_path.binread
        try_decrypt_from_env_keys(content) || try_decrypt_from_key_paths(content)
      end

      def candidate_key_paths
        Dir.glob(key_path).map { |path| Pathname.new(path) }
      end

      def candidate_env_keys
        env_key.is_a?(RegExp) ? ENV.keys.select { |k| k =~ env_key } : [env_key]
      end

      def try_decrypt(key, contents)
        encryptor = ActiveSupport::MessageEncryptor.new([ key ].pack("H*"), cipher: CIPHER)
        decrypted = encryptor.decrypt_and_verify(contents)
        @key = key
        @encryptor = encryptor
        decrypted
      rescue ActiveSupport::MessageEncryptor::InvalidMessage
        nil
      end

      def use_first_available_key
        read_env_key(candidate_env_keys.first) ||
          read_key_file(candidate_key_paths.first) ||
          handle_missing_key
      end

      def try_decrypt_from_env_keys(content)
        candidate_env_keys.find do |env_var|
          key = read_env_key(env_var)
          try_decrypt(key, content)
        end
      end

      def try_decrypt_from_key_paths(content)
        candidate_key_paths.find do |path|
          key = read_key_file(path)
          try_decrypt(key, content)
        end
      end

      def writing(contents)
        tmp_file = "#{Process.pid}.#{content_path.basename.to_s.chomp('.enc')}"
        tmp_path = Pathname.new File.join(Dir.tmpdir, tmp_file)
        tmp_path.binwrite contents

        yield tmp_path

        updated_contents = tmp_path.binread

        write(updated_contents) if updated_contents != contents
      ensure
        FileUtils.rm(tmp_path) if tmp_path.exist?
      end


      def encrypt(contents)
        encryptor.encrypt_and_sign contents
      end

      def decrypt(contents)
        encryptor.decrypt_and_verify contents
      end

      def read_env_key(env_var)
        ENV[env_var]
      end

      def read_key_file(path)
        path.binread.strip if path.exist?
      end

      def handle_missing_key
        raise MissingKeyError, key_path: key_path, env_key: env_key if raise_if_missing_key
      end
  end
end

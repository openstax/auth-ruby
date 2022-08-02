require 'spec_helper'
require 'openstax/auth/strategy_2'

RSpec.describe OpenStax::Auth::Strategy2 do

  SIGNATURE_PUBLIC_KEY = <<~SIGNATURE
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxItufComL1S+j+U2JVr4
      aeIPyZYJR8S3RcxXjlHgybrAsBf/zyAjJlOBIhVfrm9jUF1HKNMyiTKQehG5XBBW
      /F8DQT5vGdBd4g9WIAmNU0E+symeF4X+mFIZ6dYwTMKtZxv1U0nkJ8xL2q4jCFVB
      UMlQRmz9EffSz+fmXr9xGQj80HKahzciM6m2aspX096qUP90155qmLEayE2uhs5C
      oAUbahA+VXS6ggsCUeVyog5Z1mC086d8r78ylr1y8IQ3aazdJE/mKxfqvu9S423h
      wNzBP6Fp0n68ZjUdUirqAZEbSrioJgFLEzX8ef7XilTL9dKLSS1w09ErctAF+Tor
      hwIDAQAB
      -----END PUBLIC KEY-----
  SIGNATURE

  SECRETS2 = {
    # These values copied from development environment accounts.  These are not
    # used in real deployments.
    cookie_name: "oxa_dev",
    signature_public_key: SIGNATURE_PUBLIC_KEY,
    encryption_private_key: 'RvGHVZ/kvzUAA5Z3t68+FNhuMCJxkzv+',
    encryption_algorithm: 'dir',
    encryption_method: 'A256GCM',
    signature_algorithm: 'RS256'
  }

  before do
    SECRETS2.each do |name, value|
      allow(OpenStax::Auth.configuration.strategy2).to receive(name).and_return(value)
    end
  end

  let(:cookie) {
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..tD56OCg6Un6gzkTy.eQAZrea_ORzHiFvg3rmEjxjmRXlqhXIfOYA55RQP9T" \
    "uum2S7d-KqFQiNEVHvdOAz8Jt1UULezUllc1bJ42j7IiBlakUm8VlOIhS6n0XtobmuQkIV7nd_0_DNTn2uvmLC70Z9pGtgUOFm3q" \
    "XtQa5DczQTuoTQ56-_M9uewyIYtj_B0H0bfjDNvsj92hf54K8o486B97qnvfGIkb7jXRUk3q6Aa_NtNIqbmCR9Tac29H9rn7CAcV" \
    "TG2vzG-kfUwpxrA9A-LlkX4SX1LKzsD3TVQe-05Xv9cQdf8zArdeE_9KJGAdbRlM-DVK3ul2YBTy4z92uxY4cA7vtNsANb1ByNn7" \
    "K5zEa4Mnb1OcxhhrPKTTkyVWtt4-w8GhmZl48kBoeQTWEEXtRlksabKe5RhHu3-i3dXvbWBp6ALXjEkAoKC-BDDjCUt_IOErp_g0" \
    "G1CnD3aRU--lqvm2IJnKq1sncTd8qtFTm91MRPzg94O0-OHk7NohktEz3DtJjKeH0EdW98d_mon8OAf4xJDtXrADE-VxAMPhNzoF" \
    "s6o2k4t3BJpIvUj9AGuAx46vkk7B0TeIAXFy8dhq6n5vvFdYnoih1BM47DnOv5DZtABlvQv5xJTfyN23jb-QDKG-AZ--zjtamtkT" \
    "r_7GASXqbQy2xEw2QA0yQCUS6JhnRRCcrC913CU8uPtjMbzWoxkCZjCyxQkX1fcVddU9e3pmay9LZ4zZolVCOwWUp1TuEgYwSweN" \
    "pR4WiwGiWelMhHSZ3QYKjJpGyIkzCSkn7ZQRLLTe0joU43figYs790TPx4waUfwi5r3AED6OSkfxTBsjgOR9DY6083CpCZ4N7lea" \
    "XhsfepgwjiwzVw5TB4YGRg275AE4lZhdKf1lgS7OSk1S7NeMkv88ZDHnVIVAd0wiR9PZf36Ni48CArfC4btn6DT7cQURQOnQTQyi" \
    "K-WvFfkEMdWX7_Z-GRG9CCnVIT3CBBZnvoIcCaUbVmXRqv0cFJmvfsmGsA.FJxz84tw7BCYCrwYeqLpdQ"
  }

  let(:mock_request) do
    OpenStruct.new(headers: {}, cookies: { 'oxa_dev' => cookie })
  end

  context 'SSO cookie' do
    describe "#decrypt" do
      it 'decrypts' do
        decoding = described_class.decrypt(mock_request)
        expect(decoding['sub']['uuid']).to eq '1b2dc73a-a792-462b-9b0f-59bd22bac26d'
        expect(decoding['sub']['is_test']).to be_falsey
      end

      it 'returns nil on a missing cookie' do
        mock_request.cookies['oxa_dev'] = nil
        expect(described_class.decrypt(mock_request)).to be_nil
      end

      it 'returns nil on a blank cookie' do
        mock_request.cookies['oxa_dev'] = ''
        expect(described_class.decrypt(mock_request)).to be_nil
      end

      it 'returns nil on an invalid cookie' do
        mock_request.cookies['oxa_dev'] = 'bad!'
        expect(described_class.decrypt(mock_request)).to be_nil
      end
    end

    describe "#user_uuid" do
      it 'finds the user_uuid' do
        expect(described_class.user_uuid(mock_request)).to eq '1b2dc73a-a792-462b-9b0f-59bd22bac26d'
      end
    end
  end

  context 'Authorization header' do
    before { mock_request.headers['Authorization'] = "Bearer #{cookie}" }

    describe "#decrypt" do
      it 'decrypts' do
        decoding = described_class.decrypt(mock_request)
        expect(decoding['sub']['uuid']).to eq '1b2dc73a-a792-462b-9b0f-59bd22bac26d'
        expect(decoding['sub']['is_test']).to be_falsey
      end

      it 'returns nil on a blank header' do
        # If the header was completely blank or missing, it would default to the cookie
        mock_request.headers['Authorization'] = 'Bearer '
        expect(described_class.decrypt(mock_request)).to be_nil
      end

      it 'returns nil on an invalid header' do
        mock_request.headers['Authorization'] = 'Bearer bad!'
        expect(described_class.decrypt(mock_request)).to be_nil
      end
    end

    describe "#user_uuid" do
      it 'finds the user_uuid' do
        expect(described_class.user_uuid(mock_request)).to eq '1b2dc73a-a792-462b-9b0f-59bd22bac26d'
      end
    end
  end
end

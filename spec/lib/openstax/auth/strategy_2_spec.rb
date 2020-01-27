require 'spec_helper'
require 'openstax/auth/strategy_2'

RSpec.describe OpenStax::Auth::Strategy2 do
  SECRETS = {
    # these values copied from the Accounts secrets
    strategy_2_cookie_name: "oxa",
    strategy_2_signature_public_key: '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjvO/E8lO+ZJ7JMglbJyiF5/Ae\nIIS2NKbIAMLBMPVBQY7mSqo6j/yxdVNKZCzYAMDWc/VvEfXQQJ2ipIUuDvO+SOwz\nMewQ70hC71hC4s3dmOSLnixDJlnsVpcnKPEFXloObk/fcpK2Vw27e+yY+kIFmV2X\nzrvTnmm9UJERp6tVTQIDAQAB\n-----END PUBLIC KEY-----\n',
    strategy_2_encryption_private_key: 'c6d9b8683fddce8f2a39ac0565cf18ee',
    strategy_2_encryption_algorithm: 'dir',
    strategy_2_encryption_method: 'A256GCM',
    strategy_2_signature_algorithm: 'RS256'
  }

  before(:each) do
    SECRETS.each do |name, value|
      allow(OpenStax::Auth.configuration).to receive(name).and_return(value)
    end
  end

  let(:mock_request) do
    OpenStruct.new(
      cookies: {
        'oxa' => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..MBdVpgpCI_JWpcgq.ZFf9dxSRH-eNHo8AEFXBX" \
                 "2j4QsFRxSGMmEfLG8TWjeI1Pbd7UW41PdR2H7ZwOnUG0zoy6BGF-tiNWXad0mFJvkfV1u3mLnZFXJu1" \
                 "DSn3MXysUSYjQkSkNRCicKEHo_Pio7ksoZ_CticcFWG8QRHJKHAa9vQsyBm09Fnpf3TPWXyOuPUlvM4" \
                 "hCFVRTmSY3RWPf86ECpj7opVnR7G-Rgm3mB1bsUGVSH16zknaRbs2qXqR_tlpVDSBGD86hnX5cGppmq" \
                 "g6AOQAncLLpQEVZxWJrJdehxO2ylgF2PK1RmkS6A1q0DGnzFODddMWG_abro7ijpFpd2eumqniDSBSP" \
                 "QKe7EiMMoa36_YsV0m8L3kD84JgZ0XvQd4q-ZC7vL1RRYUgLCw2Lbd1l6pHNrxGF1rSB_p7KjDVkE1w" \
                 "pVc5t1wI89TLQJLPYLyejcvVsdKecAijNyrzB396uRHOkpt1Hq5qiTiKDqAkLkCKAG6Lc0bea7hT349" \
                 "x2ZexGQhHmeBCgS1LphTUef9MU0zD9eOQeF9yWl6DTMf2rW2uS_1XDKDNHXgGE-f1pLVN-vriZevQ1w" \
                 "X6eN_OpTJs3_w7ugu2deU2Guj5Ggseg05vb7eMnYu8w8Cu7VGG5s3CXwLEzXbbMMf2MOXNVPr_sHZLi" \
                 "t8WLz8dEXKTu8rvnOgLzCRXQv4q9HEUjQaL3iloBq-use5pSqkS4EqAsOxDWLertWXDfe0fXL-43qzL" \
                 "rS_ahFtQn7B4YhSvf9fEVaWcvx0st-7y7xIQP5FKVP9LWnTkhMlT2ho-7cS-91LftBn9X2oEEE4z6kD" \
                 "J1H_CUUizDDpyOrA_R2pdouos1tyhpKSqq7Th6W0Yaz_gleXoJYnX11wOBFBSefXyKgKlxUnK3DnMXa" \
                 "Wq2g66sxqJzJu6A_fJhKQ_UuiTYOlnEj-akksFGxxqe6rdkS8WmKUqzuHYT6oSKX8xTLuvcXYnVVBhc" \
                 "3cNijDIkOz9CHB62ZW733Yats4rbhquL2gRUxDYFsxc4RPcX4SfJ4v-.D0xgtTyz6N_gn9hVP9Dw5g"
      }
    )
  end

  it 'decrypts' do
    expect(described_class.decrypt(mock_request)).to eq(
                                                       'user' => {
                                                         "id"=>1,
                                                         "uuid"=>"0ae414c7-7ea7-40ed-bd6c-7f0e2269d64d",
                                                         "support_identifier"=>"cs_b5b4c957",
                                                         "is_test"=>false,
                                                         "applications"=>[]
                                                       }
                                                     )
  end

  it 'returns empty on an invalid cookie' do
    mock_request.cookies['ox'] = 'bad!'
    expect(described_class.decrypt(mock_request)).to eq({})
  end
end

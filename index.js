const fs = require('fs')
const crypto = require('crypto')
const https = require('https')
const path = require('path')

const axios = require('axios')

const keyId = "SN=499602D2" // Serial number of the downlaoded certificate in hexadecimal code

const certPath = "certs"

const httpMethod = "post"
const httpHost = "https://api.sandbox.ing.com"
const reqPath = "/oauth2/token"

const payload = "grant_type=client_credentials"
const payloadDigest = crypto.createHash('sha256').update(payload, 'utf8').digest('base64')
const digest = `SHA-256=${payloadDigest}`

const reqDate = (new Date()).toUTCString()

const signingString = `(request-target): ${httpMethod} ${reqPath}
date: ${reqDate}
digest: ${digest}`

const key = fs.readFileSync(path.join(process.cwd(), certPath, 'example_eidas_client_signing.key'))

const signature = crypto.createSign('sha256').update(signingString, 'utf8').sign({
    key,
    passphrase: 'changeit'
  }
).toString('base64')

const tlsCert = fs.readFileSync(path.join(process.cwd(), certPath, 'example_eidas_client_tls.cer'))
const tlsKey = fs.readFileSync(path.join(process.cwd(), certPath, 'example_eidas_client_tls.key'))

const httpsAgent = new https.Agent({
  cert: tlsCert,
  key: tlsKey
})

const signingCert = fs.readFileSync(path.join(process.cwd(), certPath, 'example_eidas_client_signing.cer')).toString().replace(/(\r\n|\n|\r)/gm, '')

const headers = {
  'Accept': 'application/json',
  'Content-Type': 'application/x-www-form-urlencoded',
  'Digest': `${digest}`,
  'Date': `${reqDate}`,
  'TPP-Signature-Certificate': signingCert,
  'Authorization': `Signature keyId="${keyId}",algorithm="rsa-sha256",headers="(request-target) date digest",signature="${signature}"`
}

const requestToken = async () => {
  const { status, data } = await axios.request({
    method: httpMethod,
    url: `${httpHost}${reqPath}`,
    data: payload,
    httpsAgent,
    headers
  })

  if (status === 200) {
    console.log(data)
  } else {
    console.log({ status })
    console.log(data)
  }

}

requestToken()
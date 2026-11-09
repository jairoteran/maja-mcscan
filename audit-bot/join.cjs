const mc = require('minecraft-protocol')
const [host, port, username, version] = process.argv.slice(2)
let finished = false
let client
const timer = setTimeout(() => finish('TIMEOUT: join was not confirmed', 3), 12000)

function finish(message, code) {
  if (finished) return
  finished = true
  clearTimeout(timer)
  console.log(message)
  process.exitCode = code
  if (client) client.end()
}

try {
  client = mc.createClient({ host, port: Number(port), username, version: version === 'auto' ? false : version, auth: 'offline' })
  // The play-state login packet confirms the server actually admitted the test client.
  client.on('login', () => finish('JOINED: server sent the play-state login packet', 0))
  for (const packet of ['disconnect', 'kick_disconnect']) {
    client.on(packet, data => {
      const reason = (JSON.stringify(data.reason) || 'No reason provided').replace(/[^\x20-\x7E]/g, ' ').slice(0, 500)
      finish('REJECTED: ' + reason, 2)
    })
  }
  client.on('error', error => finish('ERROR: ' + error.message, 3))
  client.on('end', () => finish('DISCONNECTED: join was not confirmed', 3))
} catch (error) {
  finish('ERROR: ' + error.message, 3)
}

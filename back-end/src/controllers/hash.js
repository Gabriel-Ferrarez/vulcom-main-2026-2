import argon2 from 'argon2'

/*
  Parâmetros do Argon2id. Geram uma codificação no formato
  $argon2id$v=19$m=65536,t=3,p=4$<sal>$<hash>, conforme exigido pelo projeto.
  O sal é gerado aleatoriamente pelo argon2.hash() e embutido na própria
  string — não é necessário gerar nem armazenar o sal separadamente.
*/
const options = {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MiB (m=65536)
  timeCost: 3,        // iterações (t=3)
  parallelism: 4      // threads (p=4)
}

// Gera o hash Argon2id da senha em texto puro
export function hashPassword(plain) {
  return argon2.hash(plain, options)
}

// Confere a senha recebida contra a codificação Argon2id armazenada.
// Os parâmetros e o sal são lidos da própria string salva.
export function verifyPassword(encoded, plain) {
  return argon2.verify(encoded, plain)
}
package io.github.styayur.wutnet

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.github.styayur.wutnet.protocol.Credential
import io.github.styayur.wutnet.protocol.ProtocolFailure
import io.github.styayur.wutnet.protocol.State
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.CharBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class CredentialStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "credential.bin"))
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private data class Stored(val username: String, val iv: ByteArray, val ciphertext: ByteArray)

    private fun key(create: Boolean): SecretKey {
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) throw ProtocolFailure(State.CredentialRequired)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }

    private fun read(): Stored = DataInputStream(file.openRead()).use {
        require(it.readInt() == 1)
        val username = it.readUTF()
        val ivSize = it.readInt()
        require(ivSize == 12)
        val iv = ByteArray(ivSize).also(it::readFully)
        val cipherSize = it.readInt()
        require(cipherSize in 16..16384)
        val ciphertext = ByteArray(cipherSize).also(it::readFully)
        require(it.read() == -1)
        Stored(username, iv, ciphertext)
    }

    @Synchronized fun username(): String? = try { read().username } catch (_: Exception) { null }

    @Synchronized fun save(username: String, password: CharArray) {
        require(username.isNotBlank() && username.length <= 256 && !username.any { it.isISOControl() })
        require(password.isNotEmpty() && password.size <= 4096)
        val encoded = Charsets.UTF_8.encode(CharBuffer.wrap(password))
        val bytes = ByteArray(encoded.remaining()).also(encoded::get)
        if (encoded.hasArray()) encoded.array().fill(0)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key(create = true))
            // Bind ciphertext to its username/version; tampering safely fails GCM verification.
            cipher.updateAAD(("WUTNet:1:$username").toByteArray(Charsets.UTF_8))
            val ciphertext = cipher.doFinal(bytes)
            val output = file.startWrite()
            try {
                val data = DataOutputStream(output)
                data.writeInt(1); data.writeUTF(username)
                data.writeInt(cipher.iv.size); data.write(cipher.iv)
                data.writeInt(ciphertext.size); data.write(ciphertext); data.flush()
                file.finishWrite(output)
            } catch (e: Exception) { file.failWrite(output); throw e }
        } finally { bytes.fill(0); password.fill('\u0000') }
    }

    @Synchronized fun load(): Credential {
        try {
            val stored = read()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(create = false), GCMParameterSpec(128, stored.iv))
            cipher.updateAAD(("WUTNet:1:${stored.username}").toByteArray(Charsets.UTF_8))
            val bytes = cipher.doFinal(stored.ciphertext)
            try {
                val decoded = Charsets.UTF_8.decode(java.nio.ByteBuffer.wrap(bytes))
                val password = CharArray(decoded.remaining()).also(decoded::get)
                if (decoded.hasArray()) decoded.array().fill('\u0000')
                return Credential(stored.username, password)
            } finally { bytes.fill(0) }
        } catch (_: Exception) {
            // Missing/inaccessible/invalidated keys never trigger plaintext fallback or key recreation.
            throw ProtocolFailure(State.CredentialRequired)
        }
    }

    @Synchronized fun clear() {
        file.delete()
        if (keyStore.containsAlias(ALIAS)) keyStore.deleteEntry(ALIAS)
    }
    companion object { private const val ALIAS = "wutnet.password.v1" }
}

package io.github.styayur.wutnet

import android.app.Activity
import android.app.AlertDialog
import android.Manifest
import android.content.pm.PackageManager
import android.net.CaptivePortal
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Parcelable
import android.view.View
import android.view.WindowManager
import io.github.styayur.wutnet.databinding.ActivityMainBinding
import io.github.styayur.wutnet.protocol.Authenticator
import io.github.styayur.wutnet.protocol.Credentials
import io.github.styayur.wutnet.protocol.Snapshot
import io.github.styayur.wutnet.protocol.State
import java.util.concurrent.Executors
import java.util.concurrent.Future

open class MainActivity : Activity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var store: CredentialStore
    private lateinit var manager: ConnectivityManager
    private val handler = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()
    private var operation: Future<*>? = null
    private var foreground = false
    private var busy = false
    private var generation = 0
    private var callbackRegistered = false
    private var autoAttempted = false
    private var pendingRefresh = false
    private var preferredNetwork: Network? = null
    private var captivePortal: CaptivePortal? = null
    private var portalHint: String? = null
    private val systemEntry: Boolean get() = this is CaptiveSignInActivity
    private val capabilitySignatures = mutableMapOf<Network, Pair<Boolean, Boolean>>()
    private val refresh = Runnable { if (foreground) runAttempt(false) }

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val signature = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) to
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
            handler.post {
                if (capabilitySignatures.put(network, signature) != signature) queueRefresh()
            }
        }
        override fun onLost(network: Network) {
            handler.post { capabilitySignatures.remove(network); queueRefresh() }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        // Target 35+ edge-to-edge: retain readable/tappable content outside system bars and IME.
        binding.root.setOnApplyWindowInsetsListener { view, insets ->
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars() or
                    android.view.WindowInsets.Type.ime() or android.view.WindowInsets.Type.displayCutout())
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            } else {
                @Suppress("DEPRECATION")
                view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop,
                    insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }
            insets
        }
        store = CredentialStore(this)
        manager = getSystemService(ConnectivityManager::class.java)
        autoAttempted = savedInstanceState?.getBoolean("autoAttempted") ?: false
        if (systemEntry && intent.action == ConnectivityManager.ACTION_CAPTIVE_PORTAL_SIGN_IN) {
            preferredNetwork = extra(ConnectivityManager.EXTRA_NETWORK, Network::class.java)
            captivePortal = extra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL, CaptivePortal::class.java)
            portalHint = intent.getStringExtra(ConnectivityManager.EXTRA_CAPTIVE_PORTAL_URL)
        }
        binding.login.setOnClickListener { runAttempt(true) }
        binding.settings.setOnClickListener {
            binding.settingsPanel.visibility = if (binding.settingsPanel.visibility == View.VISIBLE)
                View.GONE else View.VISIBLE
            if (binding.settingsPanel.visibility == View.VISIBLE) binding.username.setText(store.username() ?: "")
        }
        binding.diagnose.setOnClickListener { runAttempt(false) }
        binding.licenses.setOnClickListener {
            val text = resources.openRawResource(R.raw.third_party_notices).bufferedReader().use { it.readText() }
            AlertDialog.Builder(this).setTitle(R.string.licenses).setMessage(text)
                .setPositiveButton(android.R.string.ok, null).show()
        }
        binding.grantLocalAccess.setOnClickListener {
            if (Build.VERSION.SDK_INT >= 37) requestPermissions(arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK), 1)
        }
        binding.save.setOnClickListener { saveCredential() }
        binding.clear.setOnClickListener {
            try {
                store.clear(); binding.password.text.clear(); binding.username.text.clear()
                binding.consent.isChecked = false
                binding.accountStatus.setText(R.string.credential_cleared)
            } catch (_: Exception) { binding.accountStatus.setText(R.string.credential_error) }
        }
        updateAccount()
    }

    private fun <T : Parcelable> extra(name: String, type: Class<T>): T? = try {
        if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(name, type)
        else {
            @Suppress("DEPRECATION")
            val value = intent.getParcelableExtra<Parcelable>(name)
            if (type.isInstance(value)) type.cast(value) else null
        }
    } catch (_: RuntimeException) { null }

    override fun onStart() {
        super.onStart(); foreground = true
        try {
            // No INTERNET/VALIDATED requirement: unvalidated captive Wi-Fi must be observed too.
            manager.registerNetworkCallback(NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(), callback)
            callbackRegistered = true
        } catch (_: RuntimeException) { callbackRegistered = false }
        val automatic = hasLocalAccess() && systemEntry && preferredNetwork != null && captivePortal != null &&
            !autoAttempted && store.username() != null
        if (automatic) autoAttempted = true
        runAttempt(automatic)
    }

    override fun onStop() {
        foreground = false; generation++
        handler.removeCallbacks(refresh)
        if (callbackRegistered) {
            try { manager.unregisterNetworkCallback(callback) } catch (_: RuntimeException) { /* Already lost. */ }
            callbackRegistered = false
        }
        operation?.cancel(true); busy = false; pendingRefresh = false
        capabilitySignatures.clear(); binding.password.text.clear()
        super.onStop()
    }
    override fun onDestroy() { executor.shutdownNow(); super.onDestroy() }
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean("autoAttempted", autoAttempted)
        super.onSaveInstanceState(outState)
    }

    private fun queueRefresh() {
        if (!foreground) return
        if (busy) { pendingRefresh = true; return }
        handler.removeCallbacks(refresh); handler.postDelayed(refresh, 300)
    }
    private fun updateAccount() {
        binding.accountStatus.setText(if (store.username() == null) R.string.credential_missing
            else R.string.credential_configured)
    }
    private fun hasLocalAccess(): Boolean = Build.VERSION.SDK_INT < 37 ||
        checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 1) {
            val automatic = hasLocalAccess() && systemEntry && preferredNetwork != null &&
                captivePortal != null && !autoAttempted && store.username() != null
            if (automatic) autoAttempted = true
            runAttempt(automatic)
        }
    }
    private fun saveCredential() {
        val password = CharArray(binding.password.text.length) { binding.password.text[it] }
        binding.password.text.clear()
        val username = binding.username.text.toString().trim()
        try {
            if (username.isBlank() || password.isEmpty() || !binding.consent.isChecked) {
                binding.accountStatus.setText(R.string.credential_invalid); return
            }
            store.save(username, password)
            binding.accountStatus.setText(R.string.credential_saved)
        } catch (_: Exception) { binding.accountStatus.setText(R.string.credential_error)
        } finally { password.fill('\u0000') }
    }
    private fun setBusy(value: Boolean) {
        busy = value
        binding.progress.visibility = if (value) View.VISIBLE else View.GONE
        listOf(binding.login, binding.save, binding.clear, binding.diagnose).forEach { it.isEnabled = !value }
    }
    private fun runAttempt(login: Boolean) {
        if (!foreground || busy) return
        handler.removeCallbacks(refresh)
        val wifi = try { NetworkAccess(manager).resolve(preferredNetwork, systemEntry, capabilitySignatures.keys.toList()) }
            catch (_: RuntimeException) { null }
        if (wifi == null) {
            binding.networkStatus.setText(R.string.wifi_missing)
            binding.portalStatus.setText(R.string.wifi_missing)
            binding.diagnosticDetails.setText(R.string.wifi_missing)
            setBusy(false); return
        }
        binding.networkStatus.text = getString(R.string.wifi_status, wifi.validated, wifi.captive)
        binding.grantLocalAccess.visibility = if (hasLocalAccess()) View.GONE else View.VISIBLE
        if (!hasLocalAccess() && (wifi.captive || !wifi.validated)) {
            binding.portalStatus.setText(R.string.local_access_required)
            binding.diagnosticDetails.setText(R.string.local_access_required)
            return
        }
        updateAccount(); setBusy(true)
        val current = ++generation
        operation = executor.submit {
            try {
                val authenticator = Authenticator(NetworkHttp(wifi, manager), Credentials { store.load() }) { snapshot ->
                    handler.post { if (foreground && current == generation) show(snapshot, wifi) }
                }
                val result = authenticator.run(login, portalHint, wifi.captive)
                handler.post {
                    if (foreground && current == generation) {
                        show(result, wifi)
                        if (result.state == State.Authenticated && captivePortal != null) {
                            try { captivePortal?.reportCaptivePortalDismissed() }
                            catch (_: RuntimeException) { binding.portalStatus.setText(R.string.captive_limited) }
                        }
                    }
                }
            } catch (_: InterruptedException) { /* Foreground operation cancelled; no retry. */
            } finally {
                handler.post {
                    if (foreground && current == generation) {
                        setBusy(false)
                        if (pendingRefresh) { pendingRefresh = false; queueRefresh() }
                    }
                }
            }
        }
    }
    private fun show(snapshot: Snapshot, wifi: WifiNetwork) {
        val string = when (snapshot.state) {
            State.Online -> R.string.state_online
            State.CaptivePortal -> R.string.state_captive
            State.WhutOffline -> R.string.state_offline
            State.Authenticating -> R.string.state_authenticating
            State.Authenticated -> R.string.state_authenticated
            State.NoNetwork -> R.string.wifi_missing
            State.UntrustedPortal -> R.string.state_untrusted
            State.AuthFailed -> R.string.state_failed
            State.CsrfFailed -> R.string.state_csrf_failed
            State.PortalUnavailable -> R.string.state_unavailable
            State.TransportError -> R.string.state_transport
            State.CredentialRequired -> R.string.credential_error
        }
        binding.portalStatus.setText(string)
        if (snapshot.state == State.CredentialRequired) binding.settingsPanel.visibility = View.VISIBLE
        val d = snapshot.diagnostics
        binding.diagnosticDetails.text = getString(R.string.diagnostic_summary, wifi.validated, wifi.captive,
            d.portalDetected, d.portalTrusted, d.nasId ?: "—", d.apiBase ?: "—", d.csrf, d.account, d.internet)
    }
}

/** Only signature-permission system callers can enter this activity (see manifest). */
class CaptiveSignInActivity : MainActivity()

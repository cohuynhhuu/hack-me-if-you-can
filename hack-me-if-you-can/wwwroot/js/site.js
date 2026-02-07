// Security Workshop - JavaScript Helpers

async function callApi(url, method = 'GET', body = null) {
    const options = { method: method, headers: { 'Content-Type': 'application/json' } };
    if (body && method !== 'GET') options.body = JSON.stringify(body);
    try {
        const response = await fetch(url, options);
        const data = await response.json();
        return { success: response.ok, data: data, status: response.status };
    } catch (error) {
        return { success: false, error: error.message, status: 0 };
    }
}

function showResult(elementId, type, message, details = null) {
    const panel = document.getElementById(elementId);
    panel.className = `result-panel result-${type}`;
    let html = `<strong>${type.toUpperCase()}:</strong> ${message}`;
    if (details) html += `<pre class="mt-2 mb-0">${JSON.stringify(details, null, 2)}</pre>`;
    panel.innerHTML = html;
    panel.style.display = 'block';
}

function hideResult(elementId) {
    document.getElementById(elementId).style.display = 'none';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

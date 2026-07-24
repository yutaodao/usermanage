(function() {
    var seconds = {{ retry_after }};
    var cd = document.getElementById('countdown');
    var fill = document.getElementById('progress-fill');
    if (!cd) return;
    var timer = setInterval(function() {
        seconds--;
        if (cd) cd.textContent = seconds;
        if (fill) fill.style.width = (seconds / {{ retry_after }} * 100) + '%';
        if (seconds <= 0) {
            clearInterval(timer);
            location.reload();
        }
    }, 1000);
})();

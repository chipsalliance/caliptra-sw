
(function() {

    var selectedCell = null;

    document.body.addEventListener("mousedown", function(e) {
        if (selectedCell) {
            var log = document.getElementById(selectedCell.dataset.logId);
            if (log && !log.contains(e.target)) {
                log.style.display = "none";
                selectedCell.classList.remove("selected");
                if (selectedCell == e.target) {
                    selectedCell = null;
                    return;
                }
                selectedCell = null;
            }
        }
        if (e.target.nodeName === "TD" &&
            e.target.parentElement.parentElement.parentElement.className === 'caliptra-test-matrix') {

            var log = document.getElementById(e.target.dataset.logId);
            if (log) {
                e.preventDefault();
                if (selectedCell != null) {
                    selectedCell.classList.remove("selected");
                }
                selectedCell = e.target;
                selectedCell.classList.add("selected"); 
                var top = (selectedCell.offsetTop + selectedCell.offsetHeight);
                log.style.display = "block";
                log.style.position = "absolute";
                log.style.top = "" + top + "px";
                log.style.left = "50px";
                log.style.right = "50px";
                log.style.maxHeight = "" + Math.max(window.scrollY + window.innerHeight - top - 50, 300) + "px";
                log.scrollTo(0, 10000);
            }
        }
    });
})();

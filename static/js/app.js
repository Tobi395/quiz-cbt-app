// Disable submit buttons after click
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form").forEach(form => {
    form.addEventListener("submit", () => {
      const btn = form.querySelector("button[type='submit']");
      if (btn) {
        btn.disabled = true;
        btn.innerText = "Please wait...";
      }
    });
  });
});

//Prevent accidental clicks
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".start-exam-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const ok = confirm(
        "This exam will last 50 minutes and cannot be paused.\nDo you want to continue?"
      );
      if (!ok) {
        e.preventDefault();
      }
    });
  });
});

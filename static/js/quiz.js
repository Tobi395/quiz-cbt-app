let currentQuestion = 0;
let warnings = 0;

const questions = document.querySelectorAll(".question");
const totalQuestions = questions.length;

function showQuestion(index) {
  questions.forEach((q, i) => {
    q.style.display = i === index ? "block" : "none";
  });
}

function nextQ() {
  if (currentQuestion < totalQuestions - 1) {
    currentQuestion++;
    showQuestion(currentQuestion);
  }
}

function prevQ() {
  if (currentQuestion > 0) {
    currentQuestion--;
    showQuestion(currentQuestion);
  }
}

/* Anti-cheating */
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    warnings++;
    alert("Warning! Do not leave the examination tab.");

    if (warnings >= 2) {
      alert("Exam auto-submitted due to rule violation.");
      document.getElementById("quizForm").submit();
    }
  }
});

/* Start */
if (totalQuestions > 0) {
  showQuestion(0);
}


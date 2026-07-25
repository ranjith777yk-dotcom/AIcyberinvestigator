"use strict";

document.querySelectorAll("[data-password-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.passwordToggle);
    if (!input) return;
    const visible = input.type === "text";
    input.type = visible ? "password" : "text";
    button.setAttribute("aria-label", visible ? "Show password" : "Hide password");
    button.setAttribute("aria-pressed", String(!visible));
    button.querySelector("i").className = visible ? "bi bi-eye" : "bi bi-eye-slash";
    input.focus();
  });
});

document.querySelectorAll("[data-auth-form]").forEach((form) => {
  const fields = [...form.querySelectorAll("input[required]")];
  fields.forEach((field) => {
    field.addEventListener("input", () => {
      field.closest(".auth-field")?.classList.remove("invalid");
      field.removeAttribute("aria-invalid");
    });
  });
  form.addEventListener("submit", (event) => {
    let firstInvalid = null;
    fields.forEach((field) => {
      const invalid = !field.checkValidity();
      field.closest(".auth-field")?.classList.toggle("invalid", invalid);
      if (invalid) field.setAttribute("aria-invalid", "true");
      else field.removeAttribute("aria-invalid");
      if (invalid && !firstInvalid) firstInvalid = field;
    });
    if (firstInvalid) {
      event.preventDefault();
      firstInvalid.focus();
      return;
    }
    form.classList.add("submitting");
    form.setAttribute("aria-busy", "true");
    const submit = form.querySelector("button[type='submit']");
    submit?.setAttribute("disabled", "");
    submit?.setAttribute("aria-label", "Submitting securely");
  });
});

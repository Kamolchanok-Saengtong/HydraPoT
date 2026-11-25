// "Copy link" says Copied for a moment, so you know the click worked.
document.addEventListener("click", function (e) {
  var b = e.target.closest && e.target.closest(".ppl-copy");
  if (!b) return;
  b.classList.add("copied");
  clearTimeout(b._t);
  b._t = setTimeout(function () { b.classList.remove("copied"); }, 1800);
});

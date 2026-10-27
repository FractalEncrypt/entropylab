// The app's one modal shell. A modal is a page-level overlay holding one card:
// it dims the page, keeps keyboard focus inside the card, closes from Escape or
// a click on the dimmed page, and hands focus back to whatever opened it. Each
// module supplies only what differs: the card markup, the controls focus
// cycles through, and what dismissing means (cancel a decision, or just close).
//
// createModal({ id, className, card, focusables, onDismiss }) appends the
// hidden overlay `<div class="modal-overlay {className} no-print" id="{id}">`
// with `card` inside, and returns:
//   show(focus, opener)  reveals it, makes the page behind it inert, focuses
//                        `focus` (or the first usable control, or the card),
//                        and remembers `opener` (default: whatever had focus)
//                        to return focus to;
//   hide({ restoreFocus = true })  hides it, restores the page, and returns
//                        focus unless asked not to (a page teardown has
//                        nowhere to return it);
//   isOpen()             whether it is showing.
// `focusables` is called per keypress, so a card whose controls change between
// openings stays correct. The beta gate cannot use this: it is inlined through
// its own build token rather than the app bundle (see modal-focus.js).
import { trapModalFocus, isUsableFocusable, focusCardRoot } from "./modal-focus.js";

export const createModal = ({ id, className, card, focusables, onDismiss }) => {
  const overlay = document.createElement("div");
  overlay.className = `modal-overlay ${className} no-print`;
  overlay.id = id;
  overlay.hidden = true;
  overlay.innerHTML = card;
  document.body.append(overlay);
  // The card root carries the dialog semantics. A caller that already set a
  // role (alertdialog) or a name keeps it; the shell never invents a name.
  const cardRoot = overlay.firstElementChild;
  if (cardRoot) {
    if (!cardRoot.hasAttribute?.("role")) cardRoot.setAttribute?.("role", "dialog");
    if (!cardRoot.hasAttribute?.("aria-modal")) cardRoot.setAttribute?.("aria-modal", "true");
  }
  let opener = null;
  // Exactly what this modal changed on the page behind it, so hide() puts back
  // only that and leaves anything already inert or aria-hidden alone.
  const inerted = new Set(), hiddened = new Set();
  const setBackgroundInert = () => {
    for (const element of document.body.children ?? []) {
      if (element === overlay) continue;
      if (!element.inert) {
        element.inert = true;
        inerted.add(element);
      }
      if (!element.hasAttribute?.("aria-hidden")) {
        element.setAttribute?.("aria-hidden", "true");
        hiddened.add(element);
      }
    }
  };
  const restoreBackground = () => {
    for (const element of inerted) element.inert = false;
    for (const element of hiddened) element.removeAttribute?.("aria-hidden");
    inerted.clear();
    hiddened.clear();
  };
  const canFocus = (element) => isUsableFocusable(element, overlay) && typeof element?.focus === "function";
  const show = (focus, from = document.activeElement) => {
    opener = from;
    overlay.hidden = false;
    // An outer modal made this overlay inert when it opened; this modal is the
    // one on top now, so it must be reachable.
    overlay.inert = false;
    overlay.removeAttribute?.("aria-hidden");
    setBackgroundInert();
    const target = canFocus(focus) ? focus : focusables().find(canFocus);
    if (target) target.focus();
    else focusCardRoot(overlay);
  };
  const hide = ({ restoreFocus = true } = {}) => {
    if (overlay.hidden) return;
    overlay.hidden = true;
    restoreBackground();
    const target = opener;
    opener = null;
    if (restoreFocus && canFocus(target)) target.focus({ preventScroll: true });
  };
  trapModalFocus(overlay, focusables);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) onDismiss();
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !event.isComposing) onDismiss();
  });
  return { overlay, show, hide, isOpen: () => !overlay.hidden };
};

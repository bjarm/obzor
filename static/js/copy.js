new ClipboardJS('#copyButton');

const toastTrigger = document.getElementById('copyButton')
const toastLiveExample = document.getElementById('copyToast')
if (toastTrigger) {
  toastTrigger.addEventListener('click', () => {
    const toast = new bootstrap.Toast(toastLiveExample)

    toast.show()
  })
}
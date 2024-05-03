function initializeCopyButton() {
  new ClipboardJS('#copyButton');

  const toastTrigger = document.getElementById('copyButton')
  const toastLiveExample = document.getElementById('copyToast')
  if (toastTrigger) {
    toastTrigger.addEventListener('click', () => {
      const toast = new bootstrap.Toast(toastLiveExample)

      toast.show()
    })
  }
}


function createDatatable() {
  new DataTable('#example', {
    columnDefs: [
      { className: "td_value", targets: [0, 3] }
    ],
    paging: false,
    scrollCollapse: true,
    scrollY: '300px',
    select: true,
    layout: {
      topStart: function () {
        let toolbar = document.createElement('div');
        toolbar.innerHTML = '<b>Passive DNS</b>';

        return toolbar;
      },
      topEnd: null,
      bottomStart: {
        buttons: [
          {
            extend: 'copy',
            text: "Копировать",
            title: null,
            messageTop: null,
            header: false,
            footer: false,
            className: "btn-main",
            action: function (e, dt, node, config, cb) {
              DataTable.ext.buttons.copyHtml5.action.call(this, e, dt, node, config, cb);
              const toast = new bootstrap.Toast(copyToast);
              toast.show();
            }
          },
          {
            extend: 'excel',
            className: "btn-main"
          },
          {
            extend: 'csv',
            className: "btn-main"
          },
          {
            extend: 'pdf',
            className: "btn-main"
          },
          {
            extend: 'print',
            text: "Печать",
            className: "btn-main"
          }
        ]
      },
      bottomEnd: {
        search: {
          text: '',
          placeholder: 'Поиск по таблице'
        }
      }
    }
  }
  );
}

function showFormErrorToast() {
  if ($('#formErrorToast').length) {
    $('#formErrorToast').toast('show');
  }
}
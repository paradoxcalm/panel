document.addEventListener('DOMContentLoaded', () => {
  const initPreviewButton = (button) => {
    button.addEventListener('click', async () => {
      const form = button.closest('form');
      const selectSelector = button.dataset.templateSelect || "select[name='template_id']";
      const contextFieldSelector = button.dataset.contextField;
      const previewTargetSelector = button.dataset.previewTarget;
      const select = form ? form.querySelector(selectSelector) : document.querySelector(selectSelector);
      const contextField = form && contextFieldSelector ? form.querySelector(contextFieldSelector) : document.querySelector(contextFieldSelector || selectSelector.replace('select', 'textarea'));
      const previewTarget = previewTargetSelector ? document.querySelector(previewTargetSelector) : null;
      if (!select || !select.value) {
        alert('Выберите шаблон');
        return;
      }
      const contextValue = contextField ? contextField.value : '';
      button.disabled = true;
      if (previewTarget) {
        previewTarget.textContent = 'Рендеринг...';
      }
      try {
        const response = await fetch('/templates/render', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            template_id: select.value,
            context: contextValue,
            apply_spintax: false,
          }),
        });
        const data = await response.json();
        if (!data.ok) {
          const message = data.error || 'Ошибка предпросмотра';
          if (previewTarget) {
            previewTarget.textContent = message;
          } else {
            alert(message);
          }
          return;
        }
        if (previewTarget) {
          previewTarget.textContent = data.rendered || '';
        }
      } catch (err) {
        console.error(err);
        if (previewTarget) {
          previewTarget.textContent = 'Ошибка связи с сервером';
        }
      } finally {
        button.disabled = false;
      }
    });
  };

  document.querySelectorAll('[data-template-preview-button]').forEach(initPreviewButton);

  const templateSelect = document.querySelector('[data-template-select]');
  const contextField = document.querySelector('[data-template-context]');
  if (templateSelect && contextField) {
    const fillContext = () => {
      const option = templateSelect.selectedOptions[0];
      if (!option) {
        return;
      }
      const defaultContext = option.dataset.defaultContext;
      if (defaultContext && !contextField.value.trim()) {
        contextField.value = defaultContext;
      }
    };
    templateSelect.addEventListener('change', fillContext);
    fillContext();
  }
});

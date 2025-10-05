(function () {
  const board = document.getElementById("queue-board");
  if (!board) {
    return;
  }

  const logViewer = document.getElementById("job-log-viewer");
  const refreshButton = document.querySelector('[data-action="refresh"]');
  let jobs = [];
  let draggedJobId = null;

  async function loadJobs() {
    try {
      const response = await fetch("/api/jobs");
      if (!response.ok) {
        throw new Error("Не удалось получить очередь");
      }
      const data = await response.json();
      jobs = Array.isArray(data.jobs) ? data.jobs : [];
      renderBoard();
    } catch (error) {
      console.error(error);
      board.textContent = "Не удалось загрузить очередь.";
    }
  }

  function renderBoard() {
    board.innerHTML = "";
    const backlogColumn = createColumn("Без расписания", null);
    board.appendChild(backlogColumn);

    const today = new Date();
    for (let i = 0; i < 7; i += 1) {
      const date = new Date(today);
      date.setDate(today.getDate() + i);
      const column = createColumn(formatDateLabel(date, i === 0), date);
      board.appendChild(column);
    }

    jobs.forEach((job) => {
      const card = createCard(job);
      const column = pickColumnForJob(job);
      column.querySelector(".calendar-column-body").appendChild(card);
    });
  }

  function formatDateLabel(date, isToday) {
    return `${isToday ? "Сегодня" : date.toLocaleDateString()} (${date
      .toLocaleDateString(undefined, { weekday: "short" })
      .toLowerCase()})`;
  }

  function createColumn(label, date) {
    const column = document.createElement("div");
    column.className = "calendar-column";
    const header = document.createElement("header");
    header.className = "calendar-column-header";
    header.textContent = label;
    column.appendChild(header);
    const body = document.createElement("div");
    body.className = "calendar-column-body";
    body.dataset.dropTarget = "1";
    if (date) {
      body.dataset.date = date.toISOString().slice(0, 10);
    } else {
      body.dataset.date = "backlog";
    }
    body.addEventListener("dragover", handleDragOver);
    body.addEventListener("drop", handleDrop);
    column.appendChild(body);
    return column;
  }

  function createCard(job) {
    const card = document.createElement("article");
    card.className = `job-card status-${job.status}`;
    card.draggable = true;
    card.dataset.jobId = job.id;

    const title = document.createElement("h3");
    title.textContent = job.title;
    card.appendChild(title);

    const meta = document.createElement("p");
    meta.className = "job-meta";
    const channel = job.channel ? `Канал: ${job.channel}` : "Без канала";
    const status = `Статус: ${job.status}`;
    let schedule = "Без расписания";
    if (job.publish_at_local) {
      const tzLabel = job.timezone ? ` (${job.timezone})` : "";
      schedule = `Публикация: ${formatLocal(job.publish_at_local)}${tzLabel}`;
    }
    meta.textContent = `${channel}\n${status}\n${schedule}`;
    card.appendChild(meta);

    if (job.error_message) {
      const error = document.createElement("p");
      error.className = "job-error";
      error.textContent = job.error_message;
      card.appendChild(error);
    }

    const actions = document.createElement("div");
    actions.className = "job-actions";
    const retryButton = document.createElement("button");
    retryButton.type = "button";
    retryButton.textContent = "Повторить";
    retryButton.addEventListener("click", (event) => {
      event.stopPropagation();
      retryJob(job.id);
    });
    actions.appendChild(retryButton);

    const logsButton = document.createElement("button");
    logsButton.type = "button";
    logsButton.textContent = "Логи";
    logsButton.addEventListener("click", (event) => {
      event.stopPropagation();
      showLogs(job.id);
    });
    actions.appendChild(logsButton);
    card.appendChild(actions);

    card.addEventListener("click", () => showLogs(job.id));
    card.addEventListener("dragstart", (event) => {
      draggedJobId = job.id;
      event.dataTransfer?.setData("text/plain", String(job.id));
      event.dataTransfer?.setDragImage(card, 10, 10);
    });

    return card;
  }

  function pickColumnForJob(job) {
    if (!job.publish_at_local) {
      return board.querySelector('.calendar-column-body[data-date="backlog"]');
    }
    const datePart = job.publish_at_local.slice(0, 10);
    const column = board.querySelector(`.calendar-column-body[data-date="${datePart}"]`);
    return column || board.querySelector('.calendar-column-body[data-date="backlog"]');
  }

  function formatLocal(isoString) {
    try {
      const date = new Date(isoString);
      const options = {
        hour: "2-digit",
        minute: "2-digit",
        day: "2-digit",
        month: "2-digit",
      };
      return new Intl.DateTimeFormat(undefined, options).format(date);
    } catch (_error) {
      return isoString;
    }
  }

  function handleDragOver(event) {
    event.preventDefault();
  }

  async function handleDrop(event) {
    event.preventDefault();
    const target = event.currentTarget;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const jobId = draggedJobId || event.dataTransfer?.getData("text/plain");
    draggedJobId = null;
    if (!jobId) {
      return;
    }
    const dateValue = target.dataset.date;
    if (!dateValue) {
      return;
    }
    if (dateValue === "backlog") {
      await updateSchedule(jobId, null);
      return;
    }
    const job = jobs.find((item) => String(item.id) === String(jobId));
    const defaultTime = job && job.publish_at_local ? job.publish_at_local.slice(11, 16) : "10:00";
    const time = window.prompt(`Время публикации для ${dateValue} (чч:мм)`, defaultTime);
    if (!time) {
      return;
    }
    await updateSchedule(jobId, { date: dateValue, time });
  }

  async function updateSchedule(jobId, scheduledFor) {
    try {
      const response = await fetch("/api/schedule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ job_id: jobId, scheduled_for: scheduledFor }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || "Не удалось обновить расписание");
      }
      await loadJobs();
    } catch (error) {
      window.alert(error instanceof Error ? error.message : String(error));
    }
  }

  async function retryJob(jobId) {
    try {
      const response = await fetch(`/api/jobs/${jobId}/retry`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || "Не удалось перезапустить задание");
      }
      await loadJobs();
    } catch (error) {
      window.alert(error instanceof Error ? error.message : String(error));
    }
  }

  async function showLogs(jobId) {
    if (!logViewer) {
      return;
    }
    logViewer.textContent = "Загрузка логов...";
    try {
      const response = await fetch(`/api/jobs/${jobId}/logs`);
      if (!response.ok) {
        throw new Error("Не удалось получить логи");
      }
      const data = await response.json();
      const logs = Array.isArray(data.logs) ? data.logs : [];
      if (!logs.length) {
        logViewer.textContent = "Логи отсутствуют.";
        return;
      }
      const lines = logs
        .map((entry) => `${entry.created_at || ""} [${entry.level}] ${entry.event}${entry.message ? ` — ${entry.message}` : ""}`)
        .join("\n");
      logViewer.textContent = lines;
    } catch (error) {
      logViewer.textContent = error instanceof Error ? error.message : String(error);
    }
  }

  board.addEventListener("dragend", () => {
    draggedJobId = null;
  });

  refreshButton?.addEventListener("click", () => {
    loadJobs();
  });

  loadJobs();
})();

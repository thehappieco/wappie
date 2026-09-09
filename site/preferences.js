/* No inline script or third-party service: the same non-sensitive preferences
   follow the person between Wappie, the console, and the messaging client. */
(() => {
  'use strict';
  const languages = ['pt', 'en', 'es', 'fr', 'de'];
  const themes = ['light', 'dark', 'system'];
  const dictionaries = {
    pt: {
      description: 'Wappie: API, espaços de trabalho e cliente web para seus números do WhatsApp. Hospede você mesmo ou participe do piloto hospedado.',
      title: 'Wappie — WhatsApp para suas integrações', skip: 'Pular para o conteúdo', navigation: 'Principal', documentation: 'Documentação', signIn: 'Entrar', preferences: 'Aparência e idioma', appearance: 'Aparência', system: 'Seguir dispositivo', light: 'Claro', dark: 'Escuro', language: 'Idioma',
      heroEyebrow: 'Uma API. Seus números.', heroTitle: 'Conecte o WhatsApp ao seu jeito de trabalhar.', heroBody: 'Integre mensagens aos seus sistemas, organize números em espaços de trabalho e defina quem pode ler, enviar ou gerenciar cada um.', exploreAPI: 'Conhecer a API →', openPilot: 'Acessar o piloto', pilotNotice: 'Piloto por convite · gratuito · pagamentos simulados', example: 'Exemplo de uma conexão WebSocket', exampleConnect: '// Uma conexão, eventos em tempo real.', exampleDevices: '// Descubra seus números autorizados.',
      workspaceEyebrow: 'Seu espaço, seus acessos', workspaceTitle: 'Uma conta. Espaços para cada equipe.', integrationsNumber: '01 / INTEGRAÇÕES', permissionsTitle: 'Permissões para cada tarefa', permissionsBody: 'Contas de serviço e tokens para seus sistemas. Separe leitura, envio e gerenciamento por número e revogue acessos quando precisar.', conversationsNumber: '02 / CONVERSAS', conversationsTitle: 'Um cliente para o dia a dia', conversationsBody: 'Abra as conversas dos números aos quais você tem acesso. O console cuida dos membros, dispositivos, tokens e capacidade do espaço de trabalho.', openMessages: 'Abrir mensagens →',
      selfhostTitle: 'Rode na sua infraestrutura.', selfhostBody: 'Servidor, CLI, cliente web e administração básica disponíveis no GitHub. Controle a instalação e as atualizações.', repository: 'Ver o repositório ↗', cloudTitle: 'Ou deixe a hospedagem conosco.', cloudBody: 'A mesma base, com operação gerenciada e capacidade por espaço de trabalho. O piloto é gratuito; preços e cobrança real serão definidos antes do lançamento comercial.', invitation: 'Entrar com meu convite →', independent: 'Projeto independente, sem afiliação com WhatsApp ou Meta.', apiDocs: 'Documentação da API', source: 'Código-fonte ↗', console: 'Console',
    },
    en: {
      description: 'Wappie: an API, workspaces, and a web client for your WhatsApp numbers. Self-host or join the hosted pilot.',
      title: 'Wappie — WhatsApp for your integrations', skip: 'Skip to content', navigation: 'Main navigation', documentation: 'Documentation', signIn: 'Sign in', preferences: 'Appearance and language', appearance: 'Appearance', system: 'Use device setting', light: 'Light', dark: 'Dark', language: 'Language',
      heroEyebrow: 'One API. Your numbers.', heroTitle: 'Connect WhatsApp to the way you work.', heroBody: 'Integrate messages into your systems, organize numbers in workspaces, and choose who can read, send, or manage each one.', exploreAPI: 'Explore the API →', openPilot: 'Access the pilot', pilotNotice: 'Invitation-only pilot · free · simulated payments', example: 'Example WebSocket connection', exampleConnect: '// One connection, real-time events.', exampleDevices: '// Discover your authorized numbers.',
      workspaceEyebrow: 'Your workspace, your access', workspaceTitle: 'One account. Workspaces for every team.', integrationsNumber: '01 / INTEGRATIONS', permissionsTitle: 'Permissions for every task', permissionsBody: 'Service accounts and tokens for your systems. Separate reading, sending, and management for each number, and revoke access whenever needed.', conversationsNumber: '02 / CONVERSATIONS', conversationsTitle: 'A client for everyday conversations', conversationsBody: 'Open conversations for the numbers you can access. The console manages your workspace’s members, devices, tokens, and capacity.', openMessages: 'Open messages →',
      selfhostTitle: 'Run it on your infrastructure.', selfhostBody: 'The server, CLI, web client, and basic administration are available on GitHub. You control installation and updates.', repository: 'View the repository ↗', cloudTitle: 'Or let us handle the hosting.', cloudBody: 'The same foundation, with managed operations and capacity per workspace. The pilot is free; pricing and real billing will be defined before the commercial launch.', invitation: 'Sign in with my invitation →', independent: 'Independent project, not affiliated with WhatsApp or Meta.', apiDocs: 'API documentation', source: 'Source code ↗', console: 'Console',
    },
    es: {
      description: 'Wappie: API, espacios de trabajo y cliente web para tus números de WhatsApp. Alójalo tú mismo o participa en el piloto alojado.',
      title: 'Wappie — WhatsApp para tus integraciones', skip: 'Ir al contenido', navigation: 'Navegación principal', documentation: 'Documentación', signIn: 'Iniciar sesión', preferences: 'Apariencia e idioma', appearance: 'Apariencia', system: 'Seguir el dispositivo', light: 'Claro', dark: 'Oscuro', language: 'Idioma',
      heroEyebrow: 'Una API. Tus números.', heroTitle: 'Conecta WhatsApp con tu forma de trabajar.', heroBody: 'Integra mensajes en tus sistemas, organiza números en espacios de trabajo y define quién puede leer, enviar o gestionar cada uno.', exploreAPI: 'Conocer la API →', openPilot: 'Acceder al piloto', pilotNotice: 'Piloto por invitación · gratuito · pagos simulados', example: 'Ejemplo de conexión WebSocket', exampleConnect: '// Una conexión, eventos en tiempo real.', exampleDevices: '// Descubre tus números autorizados.',
      workspaceEyebrow: 'Tu espacio, tus accesos', workspaceTitle: 'Una cuenta. Espacios para cada equipo.', integrationsNumber: '01 / INTEGRACIONES', permissionsTitle: 'Permisos para cada tarea', permissionsBody: 'Cuentas de servicio y tokens para tus sistemas. Separa lectura, envío y gestión por número y revoca accesos cuando lo necesites.', conversationsNumber: '02 / CONVERSACIONES', conversationsTitle: 'Un cliente para el día a día', conversationsBody: 'Abre las conversaciones de los números a los que tienes acceso. La consola gestiona los miembros, dispositivos, tokens y capacidad del espacio de trabajo.', openMessages: 'Abrir mensajes →',
      selfhostTitle: 'Ejecútalo en tu infraestructura.', selfhostBody: 'Servidor, CLI, cliente web y administración básica disponibles en GitHub. Controla la instalación y las actualizaciones.', repository: 'Ver el repositorio ↗', cloudTitle: 'O deja el alojamiento en nuestras manos.', cloudBody: 'La misma base, con operación gestionada y capacidad por espacio de trabajo. El piloto es gratuito; los precios y la facturación real se definirán antes del lanzamiento comercial.', invitation: 'Entrar con mi invitación →', independent: 'Proyecto independiente, sin afiliación con WhatsApp o Meta.', apiDocs: 'Documentación de la API', source: 'Código fuente ↗', console: 'Consola',
    },
    fr: {
      description: 'Wappie : API, espaces de travail et client web pour vos numéros WhatsApp. Hébergez-le vous-même ou rejoignez le pilote hébergé.',
      title: 'Wappie — WhatsApp pour vos intégrations', skip: 'Aller au contenu', navigation: 'Navigation principale', documentation: 'Documentation', signIn: 'Se connecter', preferences: 'Apparence et langue', appearance: 'Apparence', system: 'Suivre l’appareil', light: 'Clair', dark: 'Sombre', language: 'Langue',
      heroEyebrow: 'Une API. Vos numéros.', heroTitle: 'Reliez WhatsApp à votre façon de travailler.', heroBody: 'Intégrez les messages à vos systèmes, organisez les numéros en espaces de travail et choisissez qui peut lire, envoyer ou gérer chacun d’eux.', exploreAPI: 'Découvrir l’API →', openPilot: 'Accéder au pilote', pilotNotice: 'Pilote sur invitation · gratuit · paiements simulés', example: 'Exemple de connexion WebSocket', exampleConnect: '// Une connexion, des événements en temps réel.', exampleDevices: '// Découvrez vos numéros autorisés.',
      workspaceEyebrow: 'Votre espace, vos accès', workspaceTitle: 'Un compte. Des espaces pour chaque équipe.', integrationsNumber: '01 / INTÉGRATIONS', permissionsTitle: 'Des autorisations pour chaque tâche', permissionsBody: 'Des comptes de service et des jetons pour vos systèmes. Séparez lecture, envoi et gestion par numéro, et révoquez les accès selon vos besoins.', conversationsNumber: '02 / CONVERSATIONS', conversationsTitle: 'Un client pour le quotidien', conversationsBody: 'Ouvrez les conversations des numéros auxquels vous avez accès. La console gère les membres, appareils, jetons et la capacité de l’espace de travail.', openMessages: 'Ouvrir les messages →',
      selfhostTitle: 'Utilisez votre infrastructure.', selfhostBody: 'Le serveur, la CLI, le client web et l’administration de base sont disponibles sur GitHub. Vous contrôlez l’installation et les mises à jour.', repository: 'Voir le dépôt ↗', cloudTitle: 'Ou confiez-nous l’hébergement.', cloudBody: 'La même base, avec une exploitation gérée et une capacité par espace de travail. Le pilote est gratuit ; les tarifs et la facturation réelle seront définis avant le lancement commercial.', invitation: 'Me connecter avec mon invitation →', independent: 'Projet indépendant, sans affiliation avec WhatsApp ou Meta.', apiDocs: 'Documentation de l’API', source: 'Code source ↗', console: 'Console',
    },
    de: {
      description: 'Wappie: API, Arbeitsbereiche und Webclient für Ihre WhatsApp-Nummern. Selbst hosten oder am gehosteten Pilotprojekt teilnehmen.',
      title: 'Wappie — WhatsApp für Ihre Integrationen', skip: 'Zum Inhalt springen', navigation: 'Hauptnavigation', documentation: 'Dokumentation', signIn: 'Anmelden', preferences: 'Darstellung und Sprache', appearance: 'Darstellung', system: 'Geräteeinstellung', light: 'Hell', dark: 'Dunkel', language: 'Sprache',
      heroEyebrow: 'Eine API. Ihre Nummern.', heroTitle: 'Verbinden Sie WhatsApp mit Ihrer Arbeitsweise.', heroBody: 'Integrieren Sie Nachrichten in Ihre Systeme, organisieren Sie Nummern in Arbeitsbereichen und legen Sie fest, wer jeweils lesen, senden oder verwalten darf.', exploreAPI: 'API kennenlernen →', openPilot: 'Pilotprojekt öffnen', pilotNotice: 'Pilotprojekt auf Einladung · kostenlos · simulierte Zahlungen', example: 'Beispiel einer WebSocket-Verbindung', exampleConnect: '// Eine Verbindung, Ereignisse in Echtzeit.', exampleDevices: '// Verfügbare Nummern entdecken.',
      workspaceEyebrow: 'Ihr Arbeitsbereich, Ihre Zugriffe', workspaceTitle: 'Ein Konto. Arbeitsbereiche für jedes Team.', integrationsNumber: '01 / INTEGRATIONEN', permissionsTitle: 'Berechtigungen für jede Aufgabe', permissionsBody: 'Dienstkonten und Tokens für Ihre Systeme. Trennen Sie Lesen, Senden und Verwalten je Nummer und entziehen Sie Zugriffe bei Bedarf.', conversationsNumber: '02 / GESPRÄCHE', conversationsTitle: 'Ein Client für den Alltag', conversationsBody: 'Öffnen Sie Gespräche für die Nummern, auf die Sie Zugriff haben. Die Konsole verwaltet Mitglieder, Geräte, Tokens und die Kapazität des Arbeitsbereichs.', openMessages: 'Nachrichten öffnen →',
      selfhostTitle: 'Auf Ihrer Infrastruktur betreiben.', selfhostBody: 'Server, CLI, Webclient und grundlegende Verwaltung sind auf GitHub verfügbar. Sie steuern Installation und Aktualisierungen.', repository: 'Repository ansehen ↗', cloudTitle: 'Oder überlassen Sie uns das Hosting.', cloudBody: 'Dieselbe Grundlage mit verwaltetem Betrieb und Kapazität pro Arbeitsbereich. Das Pilotprojekt ist kostenlos; Preise und reguläre Abrechnung werden vor dem kommerziellen Start festgelegt.', invitation: 'Mit meiner Einladung anmelden →', independent: 'Unabhängiges Projekt ohne Verbindung zu WhatsApp oder Meta.', apiDocs: 'API-Dokumentation', source: 'Quellcode ↗', console: 'Konsole',
    },
  };
  const read = name => {
    try {
      const value = document.cookie.split(';').map(part => part.trim()).find(part => part.startsWith(`wappie_${name}=`));
      if (value) return decodeURIComponent(value.slice(value.indexOf('=') + 1));
    } catch { /* Cookie storage is optional. */ }
    try { return localStorage.getItem(`wappie_${name}`); } catch { return null; }
  };
  const save = (name, value) => {
    try { localStorage.setItem(`wappie_${name}`, value); } catch { /* Storage is optional. */ }
    try {
      const host = location.hostname.toLowerCase();
      const shared = host === 'wappie.thehappie.co' || host.endsWith('.wappie.thehappie.co');
      document.cookie = `wappie_${name}=${encodeURIComponent(value)}; Path=/; Max-Age=31536000; SameSite=Lax${shared ? '; Domain=wappie.thehappie.co' : ''}${location.protocol === 'https:' ? '; Secure' : ''}`;
    } catch { /* The current page still updates. */ }
  };
  const media = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null;
  let theme = 'system';
  let language = 'pt';
  let ready = false;
  const applyTheme = () => { document.documentElement.dataset.theme = theme === 'system' ? (media?.matches ? 'dark' : 'light') : theme; };
  const translate = () => {
    if (!ready) return;
    const dictionary = { ...dictionaries[language], ...(globalThis.WappieDocumentationLocales?.[language] || {}) };
    document.documentElement.lang = language === 'pt' ? 'pt-BR' : language;
    document.querySelectorAll('[data-i18n]').forEach(element => {
      const value = dictionary[element.dataset.i18n];
      if (typeof value !== 'string') return;
      if (element.tagName === 'META') element.content = value;
      else element.textContent = value;
    });
    for (const [dataName, attrName] of [['i18nAria', 'aria-label'], ['i18nTitle', 'title']]) {
      document.querySelectorAll(attrName === 'title' ? '[data-i18n-title]' : '[data-i18n-aria]').forEach(element => {
        const value = dictionary[element.dataset[dataName]];
        if (typeof value === 'string') element.setAttribute(attrName, value);
      });
    }
    document.querySelectorAll('[data-theme-picker]').forEach(element => { element.value = theme; });
    document.querySelectorAll('[data-language-picker]').forEach(element => { element.value = language; });
  };
  const restore = () => {
    const storedTheme = read('theme');
    theme = themes.includes(storedTheme) ? storedTheme : 'system';
    const storedLanguage = read('locale');
    const preferred = (navigator.languages || [navigator.language || 'pt']).map(value => value.toLowerCase().split('-')[0]).find(value => languages.includes(value));
    language = languages.includes(storedLanguage) ? storedLanguage : preferred || 'en';
    applyTheme();
    translate();
  };
  restore();
  media?.addEventListener('change', applyTheme);
  document.addEventListener('DOMContentLoaded', () => {
    ready = true;
    translate();
    document.querySelectorAll('[data-theme-picker]').forEach(element => element.addEventListener('change', () => {
      if (!themes.includes(element.value)) return;
      theme = element.value;
      save('theme', theme);
      applyTheme();
    }));
    document.querySelectorAll('[data-language-picker]').forEach(element => element.addEventListener('change', () => {
      if (!languages.includes(element.value)) return;
      language = element.value;
      save('locale', language);
      translate();
    }));
    document.addEventListener('click', event => {
      document.querySelectorAll('details.preferences[open]').forEach(details => { if (!details.contains(event.target)) details.open = false; });
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') document.querySelectorAll('details.preferences[open]').forEach(details => { details.open = false; details.querySelector('summary')?.focus(); });
    });
  });
  window.addEventListener('storage', event => { if (event.key === null || event.key === 'wappie_theme' || event.key === 'wappie_locale') restore(); });
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') restore(); });
})();

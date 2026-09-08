<script setup lang="ts">
import { computed } from 'vue'

import { state } from '../state/archive'
import { stamp } from '../ui/format'

// A count, not a control. There used to be a button here, and the button had
// become a chore that never ended: rows the classifier could not name were
// offered again on every press, so an archive whose real backlog was long done
// went on reporting a hundred and thirty rows of work. The pass now runs on its
// own when the archive opens; what this panel does is say, honestly, what is
// left — by the protobuf field each row carried, which is the name of the next
// thing to implement.

const u = computed(() => state.unsupported)
const fields = computed(() => Object.entries(u.value.byField).sort((a, b) => b[1] - a[1]))
</script>

<template>
  <div class="console-panel">
    <h3>Mensagens que esta versão ainda não lê</h3>
    <p class="dim">
      Uma mensagem é classificada quando chega. Uma que entrou antes do seu tipo ser implementado
      fica como “não suportada” — mas o protobuf foi guardado selado, e toda vez que o arquivo abre
      esta aba olha de novo, com a chave que só ela tem, e converte o que a versão atual já entende.
      O que sobra está aqui, pelo nome do campo: é ele que diz o que implementar em seguida.
    </p>

    <div v-if="!state.deviceID" class="dim">Abra um aparelho no arquivo primeiro.</div>
    <div v-else-if="u.running" class="dim">Verificando…</div>
    <div v-else-if="u.error" class="alert">{{ u.error }}</div>
    <template v-else-if="u.sweptAt">
      <div class="dim" style="margin-bottom: 8px">
        Verificado às {{ stamp(u.sweptAt) }}<template v-if="u.lastRun?.changed"
          >, {{ u.lastRun.changed }} convertidas nessa passada</template
        >.
      </div>
      <div v-if="u.total === 0">
        <strong>Nenhuma.</strong> Tudo que chegou tem um tipo que esta versão entende.
      </div>
      <template v-else>
        <div><strong>{{ u.total }}</strong>, por campo do protobuf:</div>
        <div v-for="[field, n] in fields" :key="field" class="dim">· {{ field }}: {{ n }}</div>
      </template>
      <div v-if="u.lastRun?.unreadable" class="alert" style="margin-top: 6px">
        {{ u.lastRun.unreadable }} não abriram com esta chave.
      </div>
    </template>
  </div>
</template>

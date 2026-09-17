<template>
  <errors v-if="error" :errorCode="error.status" />
  <div class="row" v-else-if="!layoutStore.loading && settings !== null">
    <div class="column">
      <form class="card" @submit.prevent="save">
        <div class="card-title">
          <h2>{{ t("settings.globalSettings") }}</h2>
        </div>

        <div class="card-content">
          <p>
            <input type="checkbox" v-model="settings.signup" />
            {{ t("settings.allowSignup") }}
          </p>

          <p>
            <input type="checkbox" v-model="settings.createUserDir" />
            {{ t("settings.createUserDir") }}
          </p>

          <p>
            <input type="checkbox" v-model="settings.hideLoginButton" />
            {{ t("settings.hideLoginButton") }}
          </p>

          <p>
            <label class="small">{{ t("settings.userHomeBasePath") }}</label>
            <input
              class="input input--block"
              type="text"
              v-model="settings.userHomeBasePath"
            />
          </p>

          <p>
            <label for="minimumPasswordLength">{{
              t("settings.minimumPasswordLength")
            }}</label>
            <vue-number-input
              controls
              v-model.number="settings.minimumPasswordLength"
              id="minimumPasswordLength"
              :min="1"
            />
          </p>

          <h3>{{ t("settings.rules") }}</h3>
          <p class="small">{{ t("settings.globalRules") }}</p>
          <rules v-model:rules="settings.rules" />

          <h3>{{ t("settings.branding") }}</h3>

          <i18n-t
            keypath="settings.brandingHelp"
            tag="p"
            class="small"
            scope="global"
          >
            <a
              class="link"
              target="_blank"
              rel="noopener noreferrer"
              href="https://github.com/realalexandergeorgiev/filebrowser-ng/blob/main/docs/customization.md#custom-branding"
              >{{ t("settings.documentation") }}</a
            >
          </i18n-t>

          <p>
            <input
              type="checkbox"
              v-model="settings.branding.disableExternal"
              id="branding-links"
            />
            {{ t("settings.disableExternalLinks") }}
          </p>

          <p>
            <input
              type="checkbox"
              v-model="settings.branding.disableUsedPercentage"
              id="branding-used-disk"
            />
            {{ t("settings.disableUsedDiskPercentage") }}
          </p>

          <p>
            <label for="theme">{{ t("settings.themes.title") }}</label>
            <themes
              class="input input--block"
              v-model:theme="settings.branding.theme"
              id="theme"
            ></themes>
          </p>

          <p>
            <label for="branding-name">{{ t("settings.instanceName") }}</label>
            <input
              class="input input--block"
              type="text"
              v-model="settings.branding.name"
              id="branding-name"
            />
          </p>

          <p>
            <label for="branding-files">{{
              t("settings.brandingDirectoryPath")
            }}</label>
            <input
              class="input input--block"
              type="text"
              v-model="settings.branding.files"
              id="branding-files"
            />
          </p>

          <h3>{{ t("settings.tusUploads") }}</h3>

          <p class="small">{{ t("settings.tusUploadsHelp") }}</p>

          <div class="tusConditionalSettings">
            <p>
              <label for="tus-chunkSize">{{
                t("settings.tusUploadsChunkSize")
              }}</label>
              <input
                class="input input--block"
                type="text"
                v-model="formattedChunkSize"
                id="tus-chunkSize"
              />
            </p>

            <p>
              <label for="tus-retryCount">{{
                t("settings.tusUploadsRetryCount")
              }}</label>
              <vue-number-input
                controls
                v-model.number="settings.tus.retryCount"
                id="tus-retryCount"
                :min="0"
              />
            </p>
          </div>
        </div>

        <div class="card-action">
          <input
            class="button button--flat"
            type="submit"
            :value="t('buttons.update')"
          />
        </div>
      </form>
    </div>

    <div class="column">
      <form class="card" @submit.prevent="save">
        <div class="card-title">
          <h2>{{ t("settings.userDefaults") }}</h2>
        </div>

        <div class="card-content">
          <p class="small">{{ t("settings.defaultUserDescription") }}</p>

          <user-form
            :isNew="false"
            :isDefault="true"
            v-model:user="settings.defaults"
          />
        </div>

        <div class="card-action">
          <input
            class="button button--flat"
            type="submit"
            :value="t('buttons.update')"
          />
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { settings as api } from "@/api";
import { StatusError } from "@/api/utils";
import Rules from "@/components/settings/Rules.vue";
import Themes from "@/components/settings/Themes.vue";
import UserForm from "@/components/settings/UserForm.vue";
import { useLayoutStore } from "@/stores/layout";
import { getTheme, setTheme } from "@/utils/theme";
import Errors from "@/views/Errors.vue";
import { computed, inject, onBeforeUnmount, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const error = ref<StatusError | null>(null);
const originalSettings = ref<ISettings | null>(null);
const settings = ref<ISettings | null>(null);
const debounceTimeout = ref<number | null>(null);
const pendingChunkSize = ref<string | null>(null);

const $showError = inject<IToastError>("$showError")!;
const $showSuccess = inject<IToastSuccess>("$showSuccess")!;

const { t } = useI18n();

const layoutStore = useLayoutStore();

const formattedChunkSize = computed({
  get() {
    return settings?.value?.tus?.chunkSize
      ? formatBytes(settings?.value?.tus?.chunkSize)
      : "";
  },
  set(value: string) {
    // Use debouncing to allow the user to type freely without
    // interruption by the formatter
    // Clear the previous timeout if it exists
    if (debounceTimeout.value) {
      clearTimeout(debounceTimeout.value);
    }

    pendingChunkSize.value = value;

    // Set a new timeout to apply the format after a short delay
    debounceTimeout.value = window.setTimeout(applyChunkSize, 1500);
  },
});

// applyChunkSize commits what the user typed. Saving must flush it first:
// otherwise submitting within the debounce window persists the previous value,
// and the setting appears to refuse the change.
const applyChunkSize = () => {
  if (debounceTimeout.value) {
    clearTimeout(debounceTimeout.value);
    debounceTimeout.value = null;
  }

  if (pendingChunkSize.value === null) return;

  if (settings.value) {
    settings.value.tus.chunkSize = parseBytes(pendingChunkSize.value);
  }
  pendingChunkSize.value = null;
};

// Define funcs
const save = async () => {
  if (settings.value === null) return false;
  applyChunkSize();
  const newSettings: ISettings = { ...settings.value };

  if (newSettings.branding.theme !== getTheme()) {
    setTheme(newSettings.branding.theme);
  }

  try {
    await api.update(newSettings);
    $showSuccess(t("settings.settingsUpdated"));
  } catch (e: any) {
    $showError(e);
  }

  return true;
};
// Parse the user-friendly input (e.g., "20M" or "1T") to bytes
const parseBytes = (input: string) => {
  const regex = /^(\d+)(\.\d+)?(B|K|KB|M|MB|G|GB|T|TB)?$/i;
  const matches = input.match(regex);
  if (matches) {
    const size = parseFloat(matches[1].concat(matches[2] || ""));
    // The unit is optional: a bare number is already a count of bytes. Reading
    // it unguarded throws, and the throw happens inside the debounce callback,
    // so the setting is silently never updated.
    let unit: keyof SettingsUnit = (
      matches[3] ?? "B"
    ).toUpperCase() as keyof SettingsUnit;
    if (!unit.endsWith("B")) {
      unit += "B";
    }
    const units: SettingsUnit = {
      KB: 1024,
      MB: 1024 ** 2,
      GB: 1024 ** 3,
      TB: 1024 ** 4,
    };
    return size * (units[unit as keyof SettingsUnit] || 1);
  } else {
    return 1024 ** 2;
  }
};
// Format the chunk size in bytes to user-friendly format
const formatBytes = (bytes: number) => {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size}${units[unitIndex]}`;
};

// Define Hooks

onMounted(async () => {
  try {
    layoutStore.loading = true;
    const original: ISettings = await api.get();

    originalSettings.value = original;
    settings.value = { ...original };
  } catch (err) {
    if (err instanceof Error) {
      error.value = err;
    }
  } finally {
    layoutStore.loading = false;
  }
});

// Clear the debounce timeout when the component is destroyed
onBeforeUnmount(() => {
  if (debounceTimeout.value) {
    clearTimeout(debounceTimeout.value);
  }
});
</script>

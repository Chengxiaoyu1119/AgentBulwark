/**
 * Ant Design layout and display primitives used by the product surfaces.
 *
 * The product components intentionally import these names from `components/ui`
 * rather than from `antd` directly.  This keeps the vendor boundary in one
 * place and gives the design system a stable seam for future defaults (density,
 * typography, focus treatment and telemetry) without changing every page.
 *
 * These exports are aliases, not a second rendering implementation.  Keeping
 * the underlying Ant Design contracts intact is important: existing props,
 * refs and accessibility behaviour remain unchanged while ownership becomes
 * explicit and statically auditable.
 */
export {
  Col as UiCol,
  Collapse as UiCollapse,
  ConfigProvider as UiConfigProvider,
  Descriptions as UiDescriptions,
  Divider as UiDivider,
  Drawer as UiDrawer,
  Empty as UiEmpty,
  Flex as UiFlex,
  Form as UiForm,
  Layout as UiLayout,
  Menu as UiMenu,
  Popconfirm as UiPopconfirm,
  Row as UiRow,
  Space as UiSpace,
  Spin as UiSpin,
  Statistic as UiStatistic,
  Steps as UiSteps,
  Timeline as UiTimeline,
  Typography as UiTypography,
  theme as UiTheme
} from 'antd';

export type {
  ColProps as UiColProps,
  CollapseProps as UiCollapseProps,
  ConfigProviderProps as UiConfigProviderProps,
  DescriptionsProps as UiDescriptionsProps,
  DividerProps as UiDividerProps,
  DrawerProps as UiDrawerProps,
  EmptyProps as UiEmptyProps,
  FlexProps as UiFlexProps,
  FormItemProps as UiFormItemProps,
  FormProps as UiFormProps,
  MenuProps as UiMenuProps,
  PopconfirmProps as UiPopconfirmProps,
  RowProps as UiRowProps,
  SpaceProps as UiSpaceProps,
  StatisticProps as UiStatisticProps,
  StepsProps as UiStepsProps,
  TimelineProps as UiTimelineProps,
  TypographyProps as UiTypographyProps
} from 'antd';

export type { TableColumnsType as UiTableColumnsType } from 'antd';

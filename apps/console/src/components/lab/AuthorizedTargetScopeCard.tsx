import { Col, Row, Typography } from 'antd';
import { ShieldCheck } from 'lucide-react';
import { PanelCard } from '../ui';

export function AuthorizedTargetScopeCard() {
  return (
    <Row gutter={[20, 20]} className="zh-attack-lab__evidence-row">
      <Col xs={24}>
        <PanelCard title="可调用范围" subtitle={<ShieldCheck size={16} />}>
          <Typography.Paragraph className="zh-description-flush">
            允许路径包括 /api/agent/run、/api/chat、/api/runtime/evaluate、/api/integrations/openclaw/events、
            /api/attack_lab/run 和 /v1/chat/completions。这个限制的作用是把能力约束在 LLM/Agent 受控实验环境，
            不把作品做成任意网站攻击器。
          </Typography.Paragraph>
        </PanelCard>
      </Col>
    </Row>
  );
}

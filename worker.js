export default {
  async fetch(request, env) {
    const id = env.HEARTBEAT.idFromName("tenant:public");
    return env.HEARTBEAT.get(id).fetch(request);
  },
};

export class HeartbeatDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  async fetch() {
    return new Response("ok");
  }
}

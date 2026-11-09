import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import org.replydev.mcping.MCPinger;
import org.replydev.mcping.PingOptions;

class QuboProbe {
    public static void main(String[] args) throws IOException, InterruptedException {
        var slots = new Semaphore(16);
        try (var input = Files.newBufferedReader(Path.of(args[0]));
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            String line;
            while ((line = input.readLine()) != null) {
                var endpoint = line.split("\\t", 2);
                slots.acquire();
                executor.execute(() -> {
                    try {
                        probe(endpoint[0], Integer.parseInt(endpoint[1]));
                    } finally {
                        slots.release();
                    }
                });
                Thread.sleep(100);
            }
        }
    }

    private static void probe(String ip, int port) {
        var options = PingOptions.builder().hostname(ip).port(port).timeout(2000).build();
        try {
            var response = MCPinger.builder().pingOptions(options).build().fetchData();
            if (response == null || response.getVersion() == null) {
                return;
            }
            var players = response.getPlayers();
            var description = response.getDescription();
            System.out.println(ip + "\t" + port + "\t" + encode(response.getVersion().getName())
                    + "\t" + (players == null ? "" : players.getOnline() + "/" + players.getMax())
                    + "\t" + encode(description == null ? "" : description.getText()));
        } catch (IOException | RuntimeException ignored) {
            // An endpoint may close the connection or return a non-Minecraft packet.
        }
    }

    private static String encode(String value) {
        return value == null ? "" : Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
